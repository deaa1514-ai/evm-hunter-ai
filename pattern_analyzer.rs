//! Pattern Analyzer — يكتشف أنماط خطيرة مخفية بذكاء
use crate::reporter::{Finding, Severity};
use crate::scanner::ContractSource;

pub struct PatternAnalyzer;

impl PatternAnalyzer {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, sources: &[ContractSource]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for source in sources {
            findings.extend(self.analyze_source(&source.name, &source.content));
        }
        findings
    }

    fn analyze_source(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // تجاهل ملفات OpenZeppelin والمكتبات الموثوقة
        let lower_filename = filename.to_lowercase();
        if lower_filename.contains("openzeppelin") ||
           lower_filename.contains("@openzeppelin") ||
           lower_filename.contains("lib/") ||
           lower_filename.contains("node_modules/") ||
           lower_filename.contains("interfaces/i") {
            return findings;
        }

        findings.extend(self.detect_hidden_mint(filename, code));
        findings.extend(self.detect_owner_backdoor(filename, code));
        findings.extend(self.detect_fee_manipulation(filename, code));
        findings.extend(self.detect_blacklist_freeze(filename, code));
        findings.extend(self.detect_honeypot_patterns(filename, code));
        findings.extend(self.detect_flash_loan_attack_surface(filename, code));
        findings.extend(self.detect_price_manipulation(filename, code));
        findings.extend(self.detect_signature_replay(filename, code));
        findings.extend(self.detect_integer_overflow_patterns(filename, code));
        findings.extend(self.detect_centralization_risk(filename, code));

        findings
    }

    /// mint مخفي خلف اسم عادي
    fn detect_hidden_mint(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let suspicious_names = [
            "airdrop", "distribute", "claim", "reward", "bonus",
            "gift", "faucet", "presale", "seed", "vest",
        ];

        for line_num in 0..code.lines().count() {
            let line = code.lines().nth(line_num).unwrap_or("");
            let lower = line.to_lowercase();

            // دالة باسم بريء تحتوي على _mint داخلياً
            let is_func = lower.contains("function ") && (lower.contains("public") || lower.contains("external"));
            let has_suspicious_name = suspicious_names.iter().any(|n| lower.contains(n));

            if is_func && has_suspicious_name {
                // ابحث في الـ 20 سطر التالية عن _mint
                let body: String = code.lines()
                    .skip(line_num)
                    .take(20)
                    .collect::<Vec<_>>()
                    .join("\n");

                if body.contains("_mint(") || body.contains("mint(") {
                    findings.push(Finding {
                        id: "HIDDEN_MINT_FUNCTION".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "Function with innocent name ('{}') contains minting logic — possible hidden inflation",
                            line.trim()
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Review mint permissions — ensure only authorized roles can mint".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                    });
                }
            }
        }
        findings
    }

    /// backdoor في الـ owner — يستطيع سرقة الأموال
    fn detect_owner_backdoor(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // owner يقدر يسحب ETH مباشرة
        let patterns = [
            ("owner.*withdraw", "Owner can withdraw all ETH directly"),
            ("onlyOwner.*transfer.*balance", "Owner can transfer entire token balance"),
            ("owner.*call.*value", "Owner can execute arbitrary ETH transfers"),
            ("emergencyWithdraw", "Emergency withdraw — owner can drain funds"),
            ("rescueTokens|rescueFunds|recoverTokens", "Fund rescue function — verify access control"),
        ];

        for (line_num, line) in code.lines().enumerate() {
            let lower = line.to_lowercase();
            for (pattern, description) in &patterns {
                // simple substring check (no lookahead needed)
                let parts: Vec<&str> = pattern.split(".*").collect();
                let matches = parts.iter().all(|p| lower.contains(p));

                if matches {
                    findings.push(Finding {
                        id: "OWNER_BACKDOOR".to_string(),
                        severity: Severity::High,
                        description: format!("{} — {}", description, line.trim()),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Add timelock and multisig requirements for fund movements".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                    });
                }
            }
        }
        findings
    }

    /// رسوم متغيرة قابلة للتلاعب
    fn detect_fee_manipulation(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let fee_vars = ["fee", "tax", "buyFee", "sellFee", "transferFee", "burnFee"];

        for (line_num, line) in code.lines().enumerate() {
            let lower = line.to_lowercase();

            // دالة تعديل الـ fee
            if lower.contains("function set") && fee_vars.iter().any(|f| lower.contains(f)) {
                // هل فيها حد أقصى؟
                let body: String = code.lines()
                    .skip(line_num)
                    .take(10)
                    .collect::<Vec<_>>()
                    .join("\n");

                let has_max_check = body.contains("require") &&
                    (body.contains("<=") || body.contains("<") || body.contains("MAX"));

                if !has_max_check {
                    findings.push(Finding {
                        id: "UNCAPPED_FEE".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Fee setter function with no upper bound — owner can set fees to 100%: {}",
                            line.trim()
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Add require(newFee <= MAX_FEE) — MAX_FEE should be hardcoded".to_string()),
                        references: vec![],
                    });
                }
            }
        }
        findings
    }

    /// blacklist/freeze — يقدر يوقف أي محفظة
    fn detect_blacklist_freeze(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = ["blacklist", "blocklist", "frozen", "freeze", "banned", "blocked", "restricted"];

        for (line_num, line) in code.lines().enumerate() {
            let lower = line.to_lowercase();
            if keywords.iter().any(|k| lower.contains(k)) && lower.contains("mapping") {
                findings.push(Finding {
                    id: "BLACKLIST_MECHANISM".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Blacklist/freeze mapping detected — owner can block any address from transacting: {}",
                        line.trim()
                    ),
                    file: filename.to_string(),
                    line: (line_num + 1) as u32,
                    line_text: Some(line.trim().to_string()),
                    position: 0,
                    remediation: Some("Consider decentralized governance for blacklisting decisions".to_string()),
                    references: vec![],
                });
            }
        }
        findings
    }

    /// أنماط Honeypot — يشتري بس ما يقدر يبيع
    fn detect_honeypot_patterns(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // تحقق من وجود قيود مخفية على البيع
        let sell_blockers = [
            ("cooldown", "Transfer cooldown — may block selling"),
            ("maxWallet", "Max wallet limit — may prevent large sells"),
            ("maxTx", "Max transaction limit — may prevent large sells"),
            ("tradingEnabled", "Trading toggle — owner can disable selling"),
            ("swapEnabled", "Swap toggle — owner can disable selling"),
            ("_isExcluded", "Exclusion list — some addresses bypass restrictions"),
        ];

        let has_transfer = code.to_lowercase().contains("function _transfer") ||
                           code.to_lowercase().contains("function transfer");

        if !has_transfer { return findings; }

        for (line_num, line) in code.lines().enumerate() {
            let lower = line.to_lowercase();
            for (pattern, description) in &sell_blockers {
                if lower.contains(pattern) && (lower.contains("require") || lower.contains("if")) {
                    findings.push(Finding {
                        id: "HONEYPOT_PATTERN".to_string(),
                        severity: Severity::High,
                        description: format!("{}: {}", description, line.trim()),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Verify selling is possible for all users — test on-chain before investing".to_string()),
                        references: vec![],
                    });
                }
            }
        }
        findings
    }

    /// سطح هجوم Flash Loan
    fn detect_flash_loan_attack_surface(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // سعر يُحسب من reserve داخلي قابل للتلاعب
        let price_patterns = [
            "getReserves",
            "token0.balanceOf(address(this))",
            "token1.balanceOf(address(this))",
            "IERC20(token).balanceOf(address(this))",
        ];

        let has_price_calculation = price_patterns.iter().any(|p| code.contains(p));
        let has_swap = code.to_lowercase().contains("swap") || code.to_lowercase().contains("exchange");

        if has_price_calculation && has_swap {
            // ابحث عن السطر الأول
            for (line_num, line) in code.lines().enumerate() {
                if price_patterns.iter().any(|p| line.contains(p)) {
                    findings.push(Finding {
                        id: "FLASH_LOAN_ATTACK_SURFACE".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Price calculated from on-chain balance — vulnerable to flash loan price manipulation: {}",
                            line.trim()
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Use Chainlink price feeds or TWAP instead of spot price".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-135".to_string()],
                    });
                    break;
                }
            }
        }
        findings
    }

    /// تلاعب بالسعر عبر Uniswap
    fn detect_price_manipulation(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = code.to_lowercase();

        // استخدام balanceOf مباشرة كـ oracle
        if lower.contains("balanceof") && lower.contains("price") && !lower.contains("twap") && !lower.contains("oracle") {
            for (line_num, line) in code.lines().enumerate() {
                let ll = line.to_lowercase();
                if ll.contains("balanceof") && ll.contains("price") {
                    findings.push(Finding {
                        id: "SPOT_PRICE_ORACLE".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Spot price derived from balanceOf — manipulable in same transaction: {}",
                            line.trim()
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Use Uniswap V3 TWAP or Chainlink oracle".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-135".to_string()],
                    });
                    break;
                }
            }
        }
        findings
    }

    /// إعادة استخدام التوقيع (Signature Replay)
    fn detect_signature_replay(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = code.to_lowercase();

        let has_signature = lower.contains("ecrecover") || lower.contains("isvalidsignature");
        let has_nonce = lower.contains("nonce");
        let has_deadline = lower.contains("deadline") || lower.contains("expir");
        let has_chainid = lower.contains("chainid") || lower.contains("chain_id");

        if has_signature && (!has_nonce || !has_deadline || !has_chainid) {
            let mut missing = Vec::new();
            if !has_nonce { missing.push("nonce"); }
            if !has_deadline { missing.push("deadline/expiry"); }
            if !has_chainid { missing.push("chainId"); }

            for (line_num, line) in code.lines().enumerate() {
                let ll = line.to_lowercase();
                if ll.contains("ecrecover") || ll.contains("isvalidsignature") {
                    findings.push(Finding {
                        id: "SIGNATURE_REPLAY".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Signature validation missing: {} — vulnerable to replay attacks",
                            missing.join(", ")
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Use EIP-712 with nonce, deadline, and chainId in signed message".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-121".to_string()],
                    });
                    break;
                }
            }
        }
        findings
    }

    /// Integer overflow في Solidity < 0.8.0
    fn detect_integer_overflow_patterns(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // تحقق من إصدار Solidity
        let is_old_solidity = code.contains("pragma solidity ^0.6") ||
                              code.contains("pragma solidity ^0.7") ||
                              code.contains("pragma solidity 0.6") ||
                              code.contains("pragma solidity 0.7");

        if !is_old_solidity { return findings; }

        let has_safeMath = code.contains("SafeMath") || code.contains("using SafeMath");

        if !has_safeMath {
            for (line_num, line) in code.lines().enumerate() {
                let lower = line.to_lowercase();
                if (lower.contains("uint") || lower.contains("int")) &&
                   (line.contains("+=") || line.contains("-=") || line.contains("*=")) &&
                   !lower.contains("safeMath") {
                    findings.push(Finding {
                        id: "INTEGER_OVERFLOW_RISK".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Arithmetic operation in Solidity <0.8 without SafeMath — overflow risk: {}",
                            line.trim()
                        ),
                        file: filename.to_string(),
                        line: (line_num + 1) as u32,
                        line_text: Some(line.trim().to_string()),
                        position: 0,
                        remediation: Some("Use SafeMath or upgrade to Solidity ^0.8.0".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
                    });
                    break; // اكتفي بأول واحدة
                }
            }
        }
        findings
    }

    /// مركزية خطيرة — مفتاح واحد يتحكم بكل شيء
    fn detect_centralization_risk(&self, filename: &str, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = code.to_lowercase();

        let onlyOwner_count = lower.matches("onlyowner").count();
        let total_functions = lower.matches("function ").count();

        // أكثر من 60% من الدوال تحت onlyOwner = خطر مركزية
        if total_functions > 5 && onlyOwner_count > 0 {
            let ratio = onlyOwner_count as f64 / total_functions as f64;
            if ratio > 0.6 {
                findings.push(Finding {
                    id: "HIGH_CENTRALIZATION".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "{}/{} functions are owner-only ({:.0}%) — single point of failure/rug pull risk",
                        onlyOwner_count, total_functions, ratio * 100.0
                    ),
                    file: filename.to_string(),
                    line: 1,
                    line_text: None,
                    position: 0,
                    remediation: Some("Consider DAO governance or multisig (Gnosis Safe) for critical functions".to_string()),
                    references: vec![],
                });
            }
        }

        // renounceOwnership معطلة أو محذوفة
        if lower.contains("onlyowner") && !lower.contains("renounceownership") {
            findings.push(Finding {
                id: "NO_OWNERSHIP_RENOUNCE".to_string(),
                severity: Severity::Low,
                description: "Contract has owner but no renounceOwnership function — owner privileges are permanent".to_string(),
                file: filename.to_string(),
                line: 1,
                line_text: None,
                position: 0,
                remediation: Some("Inherit from OpenZeppelin Ownable which includes renounceOwnership".to_string()),
                references: vec![],
            });
        }

        findings
    }
}
