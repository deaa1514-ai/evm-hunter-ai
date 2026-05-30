//! Contract Context — يفهم سياق العقد قبل الفحص
//! يتحقق من: reputation, ownership, deployment, audit status

use std::collections::HashSet;
use anyhow::Result;

// ─── Known Safe Contracts ────────────────────────────

/// عقود معروفة وآمنة — نتجاهل false positives فيها
const KNOWN_SAFE: &[&str] = &[
    // Ethereum core
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
    "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC
    // PayPal/known issuers
    "0x6c3ea9036406852006290770bedfcaba0e23a0e8", // PYUSD
    // Uniswap
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", // UNI
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
    // Aave
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", // AAVE
    // Compound
    "0xc00e94cb662c3520282e6f5717214004a7f26888", // COMP
    // Chainlink
    "0x514910771af9ca656af840dff83e8264ecf986ca", // LINK
];

/// deployers معروفين وموثوقين
const KNOWN_SAFE_DEPLOYERS: &[&str] = &[
    "0x1a9c8182c09f50c8318d769245bea52c32be35bc", // Uniswap deployer
    "0x4e59b44847b379578588920ca78fbf26c0b4956c", // Common CREATE2 factory
];

/// أسماء tokens معروفة وآمنة
const KNOWN_SAFE_NAMES: &[&str] = &[
    "wrapped ether", "weth", "usd coin", "usdc", "tether", "usdt",
    "dai stablecoin", "dai", "wrapped bitcoin", "wbtc", "chainlink",
    "uniswap", "aave", "compound", "maker", "pyusd",
];

// ─── Context Result ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContractContext {
    pub address: String,
    pub is_known_safe: bool,
    pub ownership_renounced: bool,
    pub has_multisig: bool,
    pub deployer_trusted: bool,
    pub is_proxy: bool,
    pub proxy_target_verified: bool,
    pub risk_multiplier: f32,  // 0.0 = safe, 1.0 = normal, 2.0 = extra risky
    pub skip_reason: Option<String>,
    pub context_notes: Vec<String>,
}

impl ContractContext {
    pub fn should_skip(&self) -> bool {
        self.is_known_safe || self.skip_reason.is_some()
    }
}

// ─── Context Analyzer ───────────────────────────────

pub struct ContextAnalyzer {
    rpc_url: String,
}

impl ContextAnalyzer {
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }

    pub async fn analyze(
        &self,
        address: &str,
        name: &str,
        source_code: &str,
    ) -> ContractContext {
        let addr_lower = address.to_lowercase();
        let name_lower = name.to_lowercase();
        let mut context = ContractContext {
            address: address.to_string(),
            is_known_safe: false,
            ownership_renounced: false,
            has_multisig: false,
            deployer_trusted: false,
            is_proxy: false,
            proxy_target_verified: false,
            risk_multiplier: 1.0,
            skip_reason: None,
            context_notes: Vec::new(),
        };

        // ─── 1. Known Safe Check ──────────────────────
        if KNOWN_SAFE.contains(&addr_lower.as_str()) {
            context.is_known_safe = true;
            context.skip_reason = Some("Known safe contract".to_string());
            context.risk_multiplier = 0.0;
            return context;
        }

        // ─── 2. Known Safe Name ───────────────────────
        for safe_name in KNOWN_SAFE_NAMES {
            if name_lower.contains(safe_name) {
                context.is_known_safe = true;
                context.skip_reason = Some(format!("Known safe token: {}", name));
                context.risk_multiplier = 0.1;
                return context;
            }
        }

        // ─── 3. Source Code Analysis ──────────────────
        let lower = source_code.to_lowercase();

        // هل renounced ownership؟
        if lower.contains("renounceownership") && lower.contains("address(0)") {
            context.ownership_renounced = true;
            context.risk_multiplier *= 0.7;
            context.context_notes.push("⚠️ Ownership can be renounced".to_string());
        }

        // هل يستخدم OpenZeppelin؟
        if lower.contains("@openzeppelin") || lower.contains("openzeppelin/contracts") {
            context.risk_multiplier *= 0.8;
            context.context_notes.push("✅ Uses OpenZeppelin (battle-tested)".to_string());
        }

        // هل يستخدم timelock؟
        if lower.contains("timelock") || lower.contains("timelockcontroller") {
            context.risk_multiplier *= 0.6;
            context.context_notes.push("✅ Has timelock protection".to_string());
        }

        // هل يستخدم multisig pattern؟
        if lower.contains("multisig") || lower.contains("gnosis") 
            || lower.contains("safewallet") || lower.contains("2-of-") {
            context.has_multisig = true;
            context.risk_multiplier *= 0.5;
            context.context_notes.push("✅ Has multisig".to_string());
        }

        // هل proxy؟
        if lower.contains("delegatecall") || lower.contains("upgradeable") {
            context.is_proxy = true;
        }

        // ─── 4. On-chain Owner Check ──────────────────
        match self.check_owner_onchain(address).await {
            Ok(owner) => {
                let owner_lower = owner.to_lowercase();
                if owner_lower == "0x0000000000000000000000000000000000000000" {
                    context.ownership_renounced = true;
                    context.risk_multiplier *= 0.5;
                    context.context_notes.push("✅ Ownership renounced (owner = address(0))".to_string());
                } else if owner_lower.starts_with("0x") {
                    // Check if owner is a contract (multisig/timelock)
                    context.context_notes.push(format!("Owner: {}", &owner[..10]));
                }
            }
            Err(_) => {}
        }

        // ─── 5. Risk Boosters ─────────────────────────

        // عقد جديد جداً = أخطر
        // (سيتم إضافته لاحقاً مع deployment date)

        // هل يستخدم tx.origin؟
        if lower.contains("tx.origin") {
            context.risk_multiplier *= 1.5;
            context.context_notes.push("🔴 Uses tx.origin (phishing risk)".to_string());
        }

        // هل يستخدم assembly؟
        if lower.contains("assembly {") || lower.contains("assembly{") {
            context.risk_multiplier *= 1.2;
            context.context_notes.push("⚠️ Contains inline assembly".to_string());
        }

        // هل بدون events؟
        if !lower.contains("event ") && !lower.contains("emit ") {
            context.risk_multiplier *= 1.1;
            context.context_notes.push("⚠️ No events emitted (harder to monitor)".to_string());
        }

        context
    }

    async fn check_owner_onchain(&self, address: &str) -> Result<String> {
        // استدعاء owner() function
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let resp = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": address,
                    "data": "0x8da5cb5b" // owner() selector
                }, "latest"],
                "id": 1
            }))
            .send()
            .await?;

        let data: serde_json::Value = resp.json().await?;
        let result = data["result"].as_str().unwrap_or("0x");

        if result.len() >= 66 {
            // Extract address from ABI-encoded result
            let addr = format!("0x{}", &result[26..66]);
            Ok(addr)
        } else {
            Ok("0x0000000000000000000000000000000000000000".to_string())
        }
    }

    /// فلتر الـ findings بناءً على الـ context
    pub fn filter_findings_by_context(
        &self,
        findings: &[crate::reporter::Finding],
        context: &ContractContext,
        source: &str,
    ) -> Vec<crate::reporter::Finding> {
        if context.is_known_safe {
            return Vec::new();
        }

        let lower = source.to_lowercase();

        findings.iter().filter(|f| {
            // STORAGE_PROXY_TAKEOVER: تجاهل لو مش proxy فعلاً
            if f.id == "STORAGE_PROXY_TAKEOVER" {
                return lower.contains("delegatecall") 
                    || lower.contains("_implementation")
                    || lower.contains("upgradeto");
            }

            // SMART_DELEGATECALL: تجاهل لو target ثابت
            if f.id == "SMART_DELEGATECALL" || f.id == "AST_DELEGATECALL_IN_FUNCTION" {
                let desc = f.description.to_lowercase();
                // لو immutable target = آمن
                return !desc.contains("immutable target");
            }

            // SMART_PERMISSION_ESCALATION: تجاهل دوال ERC20 القياسية
            if f.id == "SMART_PERMISSION_ESCALATION" {
                let desc = f.description.to_lowercase();
                return !desc.contains("transfer'") 
                    && !desc.contains("approve'")
                    && !desc.contains("allowance'")
                    && !desc.contains("balanceof'");
            }

            // UNINITIALIZED_PROXY: تجاهل لو ownership renounced
            if f.id == "UNINITIALIZED_PROXY" && context.ownership_renounced {
                return false;
            }

            true
        }).cloned().collect()
    }
}
