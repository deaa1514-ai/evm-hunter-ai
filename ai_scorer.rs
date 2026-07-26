//! AI Scorer — Claude-powered exploit analysis
use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::fuzzer::FuzzResult;
use crate::scanner::ContractInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScore {
    pub risk_score: f32,
    pub confidence: f32,
    pub exploitable: bool,
    pub affects_funds: bool,
    pub needs_privileged_role: bool,
    pub attack_path: Vec<String>,
    pub summary: String,
    pub recommendation: String,
    pub bug_bounty_potential: String,
    pub estimated_bounty_usd: String,
}

pub struct AiScorer {
    api_key: String,
    enabled: bool,
}

impl AiScorer {
    pub fn new() -> Self {
        let api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
        let enabled = !api_key.is_empty();
        if enabled {
            tracing::info!("🤖 Claude AI scoring enabled");
        }
        Self { api_key, enabled }
    }

    pub fn is_available(&self) -> bool { self.enabled }

    pub async fn score_exploit(
        &self,
        contract: &ContractInfo,
        exploit: &FuzzResult,
        source_snippet: &str,
    ) -> Result<AiScore> {
        if !self.enabled {
            return Ok(self.heuristic_score(exploit));
        }

        let prompt = format!(
            r#"You are an elite smart contract security researcher. Analyze this confirmed exploit and provide a precise assessment.

CONTRACT: {} at {}
COMPILER: {} {}
VULNERABILITY TYPE: {}
FUZZER RESULT: {}
POC CALLDATA: {}

SOURCE CODE (relevant portion):
```solidity
{}
```

Provide ONLY a JSON response with no markdown:
{{
  "risk_score": <0.0-10.0, be precise>,
  "confidence": <0.0-1.0>,
  "exploitable": true,
  "affects_funds": <true if ETH/tokens can be stolen>,
  "needs_privileged_role": <true if requires owner/admin>,
  "attack_path": ["<step 1>", "<step 2>", "<step 3>"],
  "summary": "<precise one-sentence description of the exploit>",
  "recommendation": "<specific fix>",
  "bug_bounty_potential": "<Critical/High/Medium/Low>",
  "estimated_bounty_usd": "<e.g. $10,000-$50,000 or N/A>"
}}"#,
            contract.name, contract.address,
            contract.compiler, contract.compiler_version,
            exploit.vulnerability,
            exploit.details,
            exploit.counterexample.as_deref().unwrap_or("N/A"),
            &source_snippet[..source_snippet.len().min(3000)],
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}]
            }))
            .send()
            .await?;

        let data: serde_json::Value = resp.json().await?;
        let text = data["content"][0]["text"].as_str().unwrap_or("").to_string();
        let clean = text.replace("```json", "").replace("```", "").trim().to_string();

        match serde_json::from_str::<AiScore>(&clean) {
            Ok(score) => Ok(score),
            Err(e) => {
                tracing::warn!("AI JSON parse error: {} — using heuristic", e);
                Ok(self.heuristic_score(exploit))
            }
        }
    }

    fn heuristic_score(&self, exploit: &FuzzResult) -> AiScore {
        let has_funds = exploit.details.to_lowercase().contains("mint") ||
                       exploit.details.to_lowercase().contains("transfer") ||
                       exploit.details.to_lowercase().contains("drain");

        let risk = if exploit.exploitable {
            if has_funds { 9.5 } else { 7.5 }
        } else { 3.0 };

        AiScore {
            risk_score: risk,
            confidence: if exploit.exploitable { 0.88 } else { 0.4 },
            exploitable: exploit.exploitable,
            affects_funds: has_funds,
            needs_privileged_role: false,
            attack_path: vec![
                format!("Identify vulnerable function: {}", exploit.vulnerability),
                "Call function from any EOA address".to_string(),
                "Execute unauthorized state change".to_string(),
            ],
            summary: format!("Unauthorized access to {} confirmed by on-chain fuzzing", exploit.vulnerability),
            recommendation: "Add onlyOwner or equivalent access control modifier".to_string(),
            bug_bounty_potential: if risk >= 9.0 { "Critical".to_string() }
                                  else if risk >= 7.0 { "High".to_string() }
                                  else { "Medium".to_string() },
            estimated_bounty_usd: if risk >= 9.0 { "$50,000-$500,000".to_string() }
                                   else if risk >= 7.0 { "$10,000-$50,000".to_string() }
                                   else { "$1,000-$10,000".to_string() },
        }
    }
}
