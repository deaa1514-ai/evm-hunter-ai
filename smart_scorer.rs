//! Smart Scorer — يحسب risk score حقيقي بدل mint() = CRITICAL
//! يجمع عوامل متعددة للوصول لقرار دقيق

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub score: f32,          // 0.0 - 10.0
    pub confidence: f32,     // 0.0 - 1.0
    pub is_critical: bool,   // score >= 7.0
    pub factors: Vec<RiskFactor>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct RiskFactor {
    pub name: String,
    pub points: f32,
    pub reason: String,
}

pub struct SmartScorer;

impl SmartScorer {
    pub fn new() -> Self { Self }

    /// يحسب الـ risk score لعقد بناءً على السياق الكامل
    pub async fn score_contract(
        &self,
        address: &str,
        source_code: &str,
        trigger_pattern: &str,
        liquidity_usd: f64,
        rpc_url: &str,
    ) -> RiskScore {
        let mut factors = Vec::new();
        let lower = source_code.to_lowercase();

        // ─── 1. Trigger Pattern ──────────────────────────
        match trigger_pattern {
            "mint(address,uint256)" | "mint()" => {
                factors.push(RiskFactor {
                    name: "mint_detected".to_string(),
                    points: 1.0,
                    reason: "mint() function called".to_string(),
                });
            }
            "upgradeTo(address)" | "upgradeToAndCall(address,bytes)" => {
                factors.push(RiskFactor {
                    name: "upgrade_detected".to_string(),
                    points: 3.0,
                    reason: "Proxy upgrade detected".to_string(),
                });
            }
            "transferOwnership(address)" => {
                factors.push(RiskFactor {
                    name: "ownership_transfer".to_string(),
                    points: 2.5,
                    reason: "Ownership being transferred".to_string(),
                });
            }
            "flashLoan" => {
                factors.push(RiskFactor {
                    name: "flash_loan".to_string(),
                    points: 2.0,
                    reason: "Flash loan detected".to_string(),
                });
            }
            _ => {
                factors.push(RiskFactor {
                    name: "suspicious_call".to_string(),
                    points: 0.5,
                    reason: format!("Suspicious: {}", trigger_pattern),
                });
            }
        }

        // ─── 2. Supply Cap Check ─────────────────────────
        if !lower.contains("maxsupply") && !lower.contains("max_supply")
            && !lower.contains("_cap") && !lower.contains("totalsupply >=")
            && trigger_pattern.contains("mint") {
            factors.push(RiskFactor {
                name: "no_supply_cap".to_string(),
                points: 2.0,
                reason: "No supply cap found — unlimited minting possible".to_string(),
            });
        }

        // ─── 3. Access Control on Mint ───────────────────
        if trigger_pattern.contains("mint") {
            // فحص شامل لأنماط الـ access control
            let has_access_control = 
                lower.contains("onlyowner")
                || lower.contains("onlyminter")
                || lower.contains("onlyrole")
                || lower.contains("hasrole(")
                || lower.contains("_checkrole(")
                || lower.contains("accesscontrol")
                || lower.contains("require(msg.sender == ")
                || lower.contains("require(msg.sender ==")
                || lower.contains("minter_role")
                || lower.contains("minterrole")
                || lower.contains("bytes32 public constant")  // role definitions
                || lower.contains("granter")
                || lower.contains("_roles[")
                || lower.contains("role_admin");

            // تحقق أعمق: هل الـ mint function نفسها محمية؟
            let mint_has_modifier = {
                let mint_pos = lower.find("function mint");
                if let Some(pos) = mint_pos {
                    let snippet = &lower[pos..pos.min(lower.len()).min(pos+300)];
                    snippet.contains("onlyowner")
                    || snippet.contains("onlyminter")
                    || snippet.contains("hasrole")
                    || snippet.contains("require(msg.sender")
                    || snippet.contains("_checkrole")
                    || snippet.contains("modifier")
                } else {
                    false
                }
            };

            if !has_access_control && !mint_has_modifier {
                factors.push(RiskFactor {
                    name: "unrestricted_mint".to_string(),
                    points: 3.0,
                    reason: "mint() has no access control — anyone can call it".to_string(),
                });
            } else if has_access_control || mint_has_modifier {
                // خصم نقاط لو عنده access control
                factors.push(RiskFactor {
                    name: "mint_protected".to_string(),
                    points: -1.5,
                    reason: "mint() has access control (role/modifier)".to_string(),
                });
            }
        }

        // ─── 4. Upgradeable ──────────────────────────────
        if lower.contains("upgradeable") || lower.contains("uups") || lower.contains("upgradeto") {
            factors.push(RiskFactor {
                name: "upgradeable".to_string(),
                points: 1.0,
                reason: "Contract is upgradeable".to_string(),
            });
        }

        // ─── 5. Owner is EOA (check on-chain) ────────────
        if let Ok(owner) = self.get_owner(address, rpc_url).await {
            let owner_lower = owner.to_lowercase();
            if owner_lower != "0x0000000000000000000000000000000000000000" {
                // تحقق إذا الـ owner عقد أم EOA
                if let Ok(is_eoa) = self.is_eoa(&owner, rpc_url).await {
                    if is_eoa {
                        factors.push(RiskFactor {
                            name: "eoa_owner".to_string(),
                            points: 1.0,
                            reason: format!("Owner is EOA: {}...{}", &owner[..6], &owner[owner.len()-4..]),
                        });
                    }
                }
            } else {
                // Ownership renounced = أقل خطر
                factors.push(RiskFactor {
                    name: "renounced".to_string(),
                    points: -2.0,
                    reason: "Ownership renounced — reduces risk".to_string(),
                });
            }
        }

        // ─── 6. Liquidity ────────────────────────────────
        if liquidity_usd > 100_000.0 {
            factors.push(RiskFactor {
                name: "high_liquidity".to_string(),
                points: 2.0,
                reason: format!("High liquidity: ${:.0}", liquidity_usd),
            });
        } else if liquidity_usd > 10_000.0 {
            factors.push(RiskFactor {
                name: "medium_liquidity".to_string(),
                points: 1.0,
                reason: format!("Medium liquidity: ${:.0}", liquidity_usd),
            });
        }

        // ─── 7. Known Safe Patterns ──────────────────────
        if lower.contains("@openzeppelin") || lower.contains("openzeppelin/contracts") {
            factors.push(RiskFactor {
                name: "openzeppelin".to_string(),
                points: -1.5,
                reason: "Uses OpenZeppelin — reduces risk".to_string(),
            });
        }

        if lower.contains("timelock") || lower.contains("timelockcontroller") {
            factors.push(RiskFactor {
                name: "timelock".to_string(),
                points: -2.0,
                reason: "Has timelock — significantly reduces risk".to_string(),
            });
        }

        // ─── 8. Dangerous Patterns ───────────────────────
        if lower.contains("tx.origin") {
            factors.push(RiskFactor {
                name: "tx_origin".to_string(),
                points: 1.5,
                reason: "Uses tx.origin — phishing risk".to_string(),
            });
        }

        if lower.contains("selfdestruct") {
            factors.push(RiskFactor {
                name: "selfdestruct".to_string(),
                points: 2.0,
                reason: "Contains selfdestruct".to_string(),
            });
        }

        // ─── Calculate Final Score ───────────────────────
        let raw_score: f32 = factors.iter().map(|f| f.points).sum();
        let score = raw_score.max(0.0).min(10.0);
        
        // Confidence بناءً على كمية المعلومات
        let confidence = if source_code.len() > 1000 { 0.85 } 
                        else if source_code.len() > 100 { 0.6 }
                        else { 0.3 };

        let is_critical = score >= 6.0;

        let summary = if is_critical {
            format!("HIGH RISK: {} risk factors detected (score: {:.1})", 
                factors.iter().filter(|f| f.points > 0.0).count(), score)
        } else {
            format!("LOW RISK: score {:.1} — monitoring only", score)
        };

        RiskScore { score, confidence, is_critical, factors, summary }
    }

    async fn get_owner(&self, address: &str, rpc_url: &str) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let resp = client.post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_call",
                "params": [{"to": address, "data": "0x8da5cb5b"}, "latest"],
                "id": 1
            }))
            .send().await?;

        let data: serde_json::Value = resp.json().await?;
        let result = data["result"].as_str().unwrap_or("0x");
        if result.len() >= 66 {
            Ok(format!("0x{}", &result[26..66]))
        } else {
            Ok("0x0000000000000000000000000000000000000000".to_string())
        }
    }

    async fn is_eoa(&self, address: &str, rpc_url: &str) -> Result<bool> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let resp = client.post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }))
            .send().await?;

        let data: serde_json::Value = resp.json().await?;
        let code = data["result"].as_str().unwrap_or("0x");
        Ok(code == "0x" || code == "0x0")
    }
}
