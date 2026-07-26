//! Bytecode Analyzer — يحلل العقود غير الموثقة باستخدام cast
//! يستخرج function selectors حقيقية من الـ bytecode

use anyhow::Result;
use tracing::{info, warn};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    pub address: String,
    pub has_proxy_pattern: bool,
    pub has_delegatecall: bool,
    pub has_selfdestruct: bool,
    pub function_selectors: Vec<KnownSelector>,
    pub risk_indicators: Vec<String>,
    pub risk_score: f32,
}

#[derive(Debug, Clone)]
pub struct KnownSelector {
    pub selector: String,
    pub name: String,
    pub is_dangerous: bool,
}

// Dangerous selectors مع أسمائها
const DANGEROUS_SELECTORS: &[(&str, &str, bool)] = &[
    // (selector_hex, name, is_critical)
    ("40c10f19", "mint(address,uint256)", true),
    ("1249c58b", "mint()", true),
    ("3659cfe6", "upgradeTo(address)", true),
    ("4f1ef286", "upgradeToAndCall(address,bytes)", true),
    ("f2fde38b", "transferOwnership(address)", true),
    ("715018a6", "renounceOwnership()", false),
    ("2f2ff15d", "grantRole(bytes32,address)", true),
    ("d547741f", "revokeRole(bytes32,address)", true),
    ("9dc29fac", "burn(address,uint256)", true),
    ("42966c68", "burn(uint256)", false),
    ("8456cb59", "pause()", true),
    ("3f4ba83a", "unpause()", false),
    ("5c975abb", "paused()", false),
    ("a9059cbb", "transfer(address,uint256)", false),
    ("095ea7b3", "approve(address,uint256)", false),
    ("23b872dd", "transferFrom(address,address,uint256)", false),
    ("dd62ed3e", "allowance(address,address)", false),
    ("70a08231", "balanceOf(address)", false),
    ("18160ddd", "totalSupply()", false),
    ("8da5cb5b", "owner()", false),
];

pub struct BytecodeAnalyzer {
    rpc_url: String,
    cast_path: String,
}

impl BytecodeAnalyzer {
    pub fn new(rpc_url: String) -> Self {
        // تحقق من وجود cast
        let cast_path = which_cast();
        Self { rpc_url, cast_path }
    }

    pub async fn analyze(&self, address: &str) -> Result<BytecodeAnalysis> {
        let mut analysis = BytecodeAnalysis {
            address: address.to_string(),
            has_proxy_pattern: false,
            has_delegatecall: false,
            has_selfdestruct: false,
            function_selectors: Vec::new(),
            risk_indicators: Vec::new(),
            risk_score: 0.0,
        };

        // ─── 1. جلب الـ bytecode ─────────────────────────
        let bytecode = self.get_bytecode(address).await?;

        if bytecode.is_empty() || bytecode == "0x" {
            analysis.risk_indicators.push("Empty bytecode — EOA or self-destructed".to_string());
            return Ok(analysis);
        }

        let bytecode_lower = bytecode.to_lowercase();
        let bytecode_hex = bytecode_lower.trim_start_matches("0x");

        // ─── 2. تحليل الـ opcodes الخطيرة ───────────────
        // DELEGATECALL = f4, SELFDESTRUCT = ff
        // نبحث عن patterns في الـ bytecode
        analysis.has_delegatecall = contains_opcode(bytecode_hex, "f4");
        analysis.has_selfdestruct = contains_opcode(bytecode_hex, "ff");

        // EIP-1967 implementation slot
        let eip1967_slot = "360894a13ba1a3210667c828492db98dca3e2076635130ab13d8759af565";
        analysis.has_proxy_pattern = bytecode_hex.contains(eip1967_slot)
            || analysis.has_delegatecall;

        if analysis.has_delegatecall {
            analysis.risk_indicators.push("⚠️ DELEGATECALL opcode found".to_string());
            analysis.risk_score += 2.0;
        }
        if analysis.has_selfdestruct {
            analysis.risk_indicators.push("🔴 SELFDESTRUCT opcode found".to_string());
            analysis.risk_score += 3.0;
        }
        if analysis.has_proxy_pattern && bytecode_hex.contains(eip1967_slot) {
            analysis.risk_indicators.push("⚠️ EIP-1967 proxy slot detected".to_string());
            analysis.risk_score += 1.5;
        }

        // ─── 3. استخراج الـ selectors بـ cast ───────────
        let selectors = self.extract_selectors_with_cast(&bytecode).await;

        for selector in &selectors {
            let selector_clean = selector.trim_start_matches("0x").to_lowercase();

            // تطابق مع الـ known selectors
            for (known_sel, name, is_critical) in DANGEROUS_SELECTORS {
                if selector_clean.starts_with(known_sel) {
                    analysis.function_selectors.push(KnownSelector {
                        selector: selector_clean.clone(),
                        name: name.to_string(),
                        is_dangerous: *is_critical,
                    });

                    if *is_critical {
                        analysis.risk_score += 1.5;
                        analysis.risk_indicators.push(
                            format!("🔴 Dangerous: {}()", name)
                        );
                    }
                    break;
                }
            }
        }

        // ─── 4. تحقق من الـ contract size ───────────────
        let size = bytecode_hex.len() / 2;
        if size < 100 {
            analysis.risk_indicators.push(
                format!("ℹ️ Minimal proxy ({} bytes)", size)
            );
            analysis.risk_score += 0.5;
        } else if size > 20000 {
            analysis.risk_indicators.push(
                format!("ℹ️ Large contract ({} bytes)", size)
            );
        }

        analysis.risk_score = analysis.risk_score.min(10.0);
        Ok(analysis)
    }

    async fn get_bytecode(&self, address: &str) -> Result<String> {
        // أولاً جرب cast
        if !self.cast_path.is_empty() {
            let output = Command::new(&self.cast_path)
                .args(["code", address, "--rpc-url", &self.rpc_url])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !code.is_empty() && code != "0x" {
                        return Ok(code);
                    }
                }
            }
        }

        // fallback: RPC مباشرة
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()?;

        let resp = client.post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }))
            .send().await?;

        let data: serde_json::Value = resp.json().await?;
        let code = data["result"].as_str().unwrap_or("0x").to_string();
        Ok(code)
    }

    async fn extract_selectors_with_cast(&self, bytecode: &str) -> Vec<String> {
        if self.cast_path.is_empty() {
            // fallback: manual extraction
            return extract_selectors_manual(bytecode);
        }

        // cast selectors <bytecode>
        let output = Command::new(&self.cast_path)
            .args(["selectors", bytecode])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                text.lines()
                    .filter_map(|line| {
                        // كل سطر: "0x40c10f19  mint(address,uint256)"
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        parts.first().map(|s| s.to_string())
                    })
                    .collect()
            }
            _ => {
                warn!("cast selectors failed — using manual extraction");
                extract_selectors_manual(bytecode)
            }
        }
    }

    pub fn format_analysis(analysis: &BytecodeAnalysis) -> String {
        let mut out = format!(
            "   📊 Bytecode Analysis (risk: {:.1}/10)\n",
            analysis.risk_score
        );

        for indicator in &analysis.risk_indicators {
            out.push_str(&format!("      {}\n", indicator));
        }

        let dangerous: Vec<_> = analysis.function_selectors.iter()
            .filter(|s| s.is_dangerous)
            .collect();

        if !dangerous.is_empty() {
            out.push_str("   🔴 Dangerous functions:\n");
            for s in &dangerous {
                out.push_str(&format!("      0x{} → {}\n", &s.selector[..8.min(s.selector.len())], s.name));
            }
        }

        let safe: Vec<_> = analysis.function_selectors.iter()
            .filter(|s| !s.is_dangerous)
            .collect();

        if !safe.is_empty() {
            out.push_str(&format!("   ℹ️  {} standard functions detected\n", safe.len()));
        }

        out
    }
}

// ─── Helper Functions ────────────────────────────────

fn which_cast() -> String {
    // تحقق من مسارات cast المعروفة
    let paths = [
        "/root/.foundry/bin/cast",
        "/usr/local/bin/cast",
        "cast",
    ];

    for path in &paths {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
        // جرب which
        if let Ok(out) = Command::new("which").arg(path).output() {
            if out.status.success() {
                return String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
    }
    String::new()
}

/// استخراج يدوي للـ selectors من الـ bytecode
/// يبحث عن patterns مثل PUSH4 + 4 bytes
fn extract_selectors_manual(bytecode: &str) -> Vec<String> {
    let hex = bytecode.trim_start_matches("0x").to_lowercase();
    let mut selectors = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // PUSH4 opcode = 63
    let bytes: Vec<u8> = (0..hex.len()-1)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
        .collect();

    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 { // PUSH4
            let sel = format!("{:02x}{:02x}{:02x}{:02x}",
                bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]);
            if seen.insert(sel.clone()) {
                selectors.push(format!("0x{}", sel));
            }
        }
    }

    selectors
}

/// تحقق من وجود opcode في الـ bytecode
fn contains_opcode(bytecode_hex: &str, opcode: &str) -> bool {
    // بسيط: يبحث عن الـ opcode في الـ hex
    // في المستقبل: يمكن تحسينه بـ proper disassembly
    let bytes: Vec<u8> = (0..bytecode_hex.len()-1)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&bytecode_hex[i..i+2], 16).ok())
        .collect();

    let target = u8::from_str_radix(opcode, 16).unwrap_or(0);

    // DELEGATECALL (f4) و SELFDESTRUCT (ff) نبحث عنهم
    bytes.contains(&target)
}
