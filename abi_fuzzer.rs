//! ABI-based Fuzzer — يفحص العقود غير الموثقة بدون source code
//! يستخدم cast لاستدعاء الـ dangerous selectors مباشرة

use anyhow::Result;
use tracing::{info, warn};
use std::process::Command;
use crate::bytecode_analyzer::BytecodeAnalysis;

#[derive(Debug, Clone)]
pub struct AbiFuzzResult {
    pub address: String,
    pub selector: String,
    pub function_name: String,
    pub is_vulnerable: bool,
    pub vulnerability_type: VulnType,
    pub details: String,
    pub poc_calldata: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnType {
    UnprotectedMint,
    UnprotectedUpgrade,
    UnprotectedOwnershipTransfer,
    UnprotectedBurn,
    ArbitraryCall,
    None,
}

pub struct AbiFuzzer {
    rpc_url: String,
    cast_path: String,
}

impl AbiFuzzer {
    pub fn new(rpc_url: String) -> Self {
        let cast_path = find_cast();
        Self { rpc_url, cast_path }
    }

    /// الدالة الرئيسية — تفحص العقد باستخدام الـ selectors المكتشفة
    pub async fn fuzz_unverified(
        &self,
        address: &str,
        analysis: &BytecodeAnalysis,
    ) -> Vec<AbiFuzzResult> {
        let mut results = Vec::new();

        if self.cast_path.is_empty() {
            warn!("cast not found — skipping ABI fuzzing");
            return results;
        }

        println!("   🔬 ABI Fuzzing {} dangerous selectors...",
            analysis.function_selectors.iter().filter(|s| s.is_dangerous).count()
        );

        for selector in &analysis.function_selectors {
            if !selector.is_dangerous { continue; }

            let result = match selector.name.as_str() {
                "mint(address,uint256)" => {
                    self.test_unprotected_mint(address, &selector.selector).await
                }
                "mint()" => {
                    self.test_unprotected_mint_no_args(address, &selector.selector).await
                }
                "upgradeTo(address)" | "upgradeToAndCall(address,bytes)" => {
                    self.test_unprotected_upgrade(address, &selector.selector, &selector.name).await
                }
                "transferOwnership(address)" => {
                    self.test_unprotected_ownership(address, &selector.selector).await
                }
                "burn(address,uint256)" | "burn(uint256)" => {
                    self.test_unprotected_burn(address, &selector.selector, &selector.name).await
                }
                _ => None,
            };

            if let Some(r) = result {
                if r.is_vulnerable {
                    println!("   🚨 VULNERABLE: {} — {}", r.function_name, r.details);
                } else {
                    println!("   🟢 Protected: {}", r.function_name);
                }
                results.push(r);
            }
        }

        results
    }

    /// تحقق إذا mint(address,uint256) محمية
    async fn test_unprotected_mint(
        &self,
        address: &str,
        _selector: &str,
    ) -> Option<AbiFuzzResult> {
        // نستدعي mint بعنوان عشوائي وكمية كبيرة
        let attacker = "0x000000000000000000000000000000000000dead";
        let amount = "1000000000000000000000000"; // 1M tokens

        // أولاً: نجرب static call (بدون gas) لمعرفة إذا يرفض
        let static_result = self.cast_call(
            address,
            &format!("mint(address,uint256)(bool)"),
            &[attacker, amount],
        ).await;

        // ثم نتحقق من totalSupply قبل وبعد
        let supply_before = self.get_total_supply(address).await.unwrap_or(0);

        // نحاول الاستدعاء
        let call_result = self.cast_call(
            address,
            "mint(address,uint256)",
            &[attacker, amount],
        ).await;

        // تحقق من الـ revert
        let is_protected = call_result.as_deref()
            .map(|r| r.contains("revert") 
                || r.contains("Ownable") 
                || r.contains("AccessControl")
                || r.contains("Not the owner")
                || r.contains("caller is not")
                || r.contains("unauthorized")
                || r.contains("Unauthorized")
                || r.contains("Error"))
            .unwrap_or(true);

        Some(AbiFuzzResult {
            address: address.to_string(),
            selector: "40c10f19".to_string(),
            function_name: "mint(address,uint256)".to_string(),
            is_vulnerable: !is_protected,
            vulnerability_type: if !is_protected { VulnType::UnprotectedMint } else { VulnType::None },
            details: if !is_protected {
                format!("mint() did not revert — possible unauthorized minting!")
            } else {
                "mint() reverts — access control present".to_string()
            },
            poc_calldata: Some(format!(
                "cast call {} 'mint(address,uint256)' {} {}",
                address, attacker, amount
            )),
        })
    }

    async fn test_unprotected_mint_no_args(
        &self,
        address: &str,
        _selector: &str,
    ) -> Option<AbiFuzzResult> {
        let call_result = self.cast_call(address, "mint()", &[]).await;

        let is_protected = call_result.as_deref()
            .map(|r| r.contains("revert") || r.contains("Ownable") || r.contains("AccessControl") || r.contains("Error"))
            .unwrap_or(true);

        Some(AbiFuzzResult {
            address: address.to_string(),
            selector: "1249c58b".to_string(),
            function_name: "mint()".to_string(),
            is_vulnerable: !is_protected,
            vulnerability_type: if !is_protected { VulnType::UnprotectedMint } else { VulnType::None },
            details: if !is_protected {
                "mint() did not revert — possible unauthorized minting!".to_string()
            } else {
                "mint() reverts — protected".to_string()
            },
            poc_calldata: Some(format!("cast call {} 'mint()'", address)),
        })
    }

    async fn test_unprotected_upgrade(
        &self,
        address: &str,
        _selector: &str,
        function_name: &str,
    ) -> Option<AbiFuzzResult> {
        // نجرب upgradeTo بعنوان وهمي
        let fake_impl = "0x000000000000000000000000000000000000dead";

        let call_result = self.cast_call(
            address,
            &format!("{}(address)", if function_name.contains("AndCall") { "upgradeToAndCall" } else { "upgradeTo" }),
            &[fake_impl],
        ).await;

        let is_protected = call_result.as_deref()
            .map(|r| r.contains("revert") || r.contains("Ownable") || r.contains("Error"))
            .unwrap_or(true);

        Some(AbiFuzzResult {
            address: address.to_string(),
            selector: "3659cfe6".to_string(),
            function_name: function_name.to_string(),
            is_vulnerable: !is_protected,
            vulnerability_type: if !is_protected { VulnType::UnprotectedUpgrade } else { VulnType::None },
            details: if !is_protected {
                "upgradeTo() did not revert — PROXY TAKEOVER POSSIBLE!".to_string()
            } else {
                "upgradeTo() reverts — protected".to_string()
            },
            poc_calldata: Some(format!("cast call {} 'upgradeTo(address)' {}", address, fake_impl)),
        })
    }

    async fn test_unprotected_ownership(
        &self,
        address: &str,
        _selector: &str,
    ) -> Option<AbiFuzzResult> {
        let attacker = "0x000000000000000000000000000000000000dead";

        let call_result = self.cast_call(
            address,
            "transferOwnership(address)",
            &[attacker],
        ).await;

        let is_protected = call_result.as_deref()
            .map(|r| r.contains("revert") || r.contains("Ownable") || r.contains("Error"))
            .unwrap_or(true);

        Some(AbiFuzzResult {
            address: address.to_string(),
            selector: "f2fde38b".to_string(),
            function_name: "transferOwnership(address)".to_string(),
            is_vulnerable: !is_protected,
            vulnerability_type: if !is_protected { VulnType::UnprotectedOwnershipTransfer } else { VulnType::None },
            details: if !is_protected {
                "transferOwnership() did not revert — ownership can be stolen!".to_string()
            } else {
                "transferOwnership() reverts — protected".to_string()
            },
            poc_calldata: Some(format!("cast call {} 'transferOwnership(address)' {}", address, attacker)),
        })
    }

    async fn test_unprotected_burn(
        &self,
        address: &str,
        _selector: &str,
        function_name: &str,
    ) -> Option<AbiFuzzResult> {
        let call_result = if function_name.contains("address") {
            let victim = "0x000000000000000000000000000000000000dead";
            let amount = "1000000000000000000";
            self.cast_call(address, "burn(address,uint256)", &[victim, amount]).await
        } else {
            self.cast_call(address, "burn(uint256)", &["1000000000000000000"]).await
        };

        let is_protected = call_result.as_deref()
            .map(|r| r.contains("revert") || r.contains("Error"))
            .unwrap_or(true);

        Some(AbiFuzzResult {
            address: address.to_string(),
            selector: "42966c68".to_string(),
            function_name: function_name.to_string(),
            is_vulnerable: !is_protected,
            vulnerability_type: if !is_protected { VulnType::UnprotectedBurn } else { VulnType::None },
            details: if !is_protected {
                "burn() did not revert — tokens can be burned by anyone!".to_string()
            } else {
                "burn() reverts — protected".to_string()
            },
            poc_calldata: None,
        })
    }

    async fn cast_call(
        &self,
        address: &str,
        sig: &str,
        args: &[&str],
    ) -> Option<String> {
        let mut cmd = Command::new(&self.cast_path);
        cmd.arg("call")
           .arg(address)
           .arg(sig)
           .args(args)
           .arg("--rpc-url")
           .arg(&self.rpc_url)
           // محاولة من عنوان عشوائي — مش المالك
           .arg("--from")
           .arg("0x1234567890123456789012345678901234567890");

        match cmd.output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let combined = format!("{}{}", stdout, stderr);
                // لو exit code غير صفر = revert
                if !out.status.success() {
                    Some(format!("revert {}", combined))
                } else {
                    Some(combined)
                }
            }
            Err(e) => {
                warn!("cast call failed: {}", e);
                None
            }
        }
    }

    async fn get_total_supply(&self, address: &str) -> Option<u128> {
        let result = self.cast_call(address, "totalSupply()(uint256)", &[]).await?;
        result.trim().parse().ok()
    }
}

fn find_cast() -> String {
    let paths = [
        "/root/.foundry/bin/cast",
        "/usr/local/bin/cast",
    ];
    for path in &paths {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    String::new()
}
