use anyhow::{Result, Context};
use reqwest;
use serde_json::Value;
use regex::Regex;
use std::collections::HashMap;

use crate::reporter::{Finding, Severity};

#[derive(Debug, Clone)]
pub enum Chain {
    Ethereum,
    Base,
    Arbitrum,
    Optimism,
    Polygon,
}

impl Chain {
    pub fn api_url(&self) -> &'static str {
        // Etherscan V2 unified endpoint
        "https://api.etherscan.io/v2/api"
    }

    pub fn chain_id(&self) -> u32 {
        match self {
            Chain::Ethereum => 1,
            Chain::Base     => 8453,
            Chain::Arbitrum => 42161,
            Chain::Optimism => 10,
            Chain::Polygon  => 137,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chain::Ethereum => "ethereum",
            Chain::Base     => "base",
            Chain::Arbitrum => "arbitrum",
            Chain::Optimism => "optimism",
            Chain::Polygon  => "polygon",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContractSource {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub address: String,
    pub name: String,
    pub compiler: String,
    pub compiler_version: String,
    pub sources: Vec<ContractSource>,
    pub is_proxy: bool,
    pub implementation: Option<String>,
}

pub struct ContractScanner {
    pub chain: Chain,
    api_key: String,
    client: reqwest::Client,
    patterns: Vec<(String, Regex, Severity, String)>,
}

impl ContractScanner {
    pub fn new(chain: Chain, api_key: String) -> Self {
        let patterns = Self::build_patterns();
        Self {
            chain,
            api_key,
            client: reqwest::Client::new(),
            patterns,
        }
    }

    fn build_patterns() -> Vec<(String, Regex, Severity, String)> {
        vec![
            (
                "TX_ORIGIN_AUTH".to_string(),
                Regex::new(r"tx\.origin\s*==\s*[^;]+").unwrap(),
                Severity::Critical,
                "Authorization based on tx.origin is vulnerable to phishing attacks.".to_string(),
            ),
            (
                "DELEGATECALL_UNCHECKED".to_string(),
                Regex::new(r"\.delegatecall\s*\(").unwrap(),
                Severity::Critical,
                "Unchecked delegatecall can lead to arbitrary code execution.".to_string(),
            ),
            (
                "SELFDESTRUCT_ACCESS".to_string(),
                Regex::new(r"selfdestruct\s*\(").unwrap(),
                Severity::Critical,
                "Contract can be destroyed, potentially locking funds.".to_string(),
            ),
            (
                "UNSAFE_ERC20_TRANSFER".to_string(),
                Regex::new(r"\.transfer\s*\(|\.send\s*\(").unwrap(),
                Severity::High,
                "Using transfer/send limits gas to 2300, which may break with future gas cost changes.".to_string(),
            ),
            (
                "ASSEMBLY_USAGE".to_string(),
                Regex::new(r"assembly\s*\{").unwrap(),
                Severity::Low,
                "Inline assembly bypasses Solidity safety checks.".to_string(),
            ),
            (
                "BLOCK_TIMESTAMP_DEPENDENCE".to_string(),
                Regex::new(r"block\.timestamp|block\.number").unwrap(),
                Severity::Medium,
                "Dependence on block.timestamp/number can be manipulated by validators.".to_string(),
            ),
            (
                "ECRECOVER_MALLEABILITY".to_string(),
                Regex::new(r"ecrecover\s*\(").unwrap(),
                Severity::Medium,
                "ecrecover is vulnerable to signature malleability. Use OpenZeppelin ECDSA instead.".to_string(),
            ),
            (
                "UNCHECKED_CALL_RETURN".to_string(),
                Regex::new(r"call\s*\{[^}]*value:").unwrap(),
                Severity::High,
                "Low-level call with value — ensure return value is checked.".to_string(),
            ),
            (
                "UNPROTECTED_FUNCTION".to_string(),
                Regex::new(r"function\s+\w+\s*\([^)]*\)\s*(public|external)\s+[^;{]*\{").unwrap(),
                Severity::Medium,
                "Public/external non-view function — verify access control is in place.".to_string(),
            ),
            (
                "HARDCODED_ADDRESS".to_string(),
                Regex::new(r"0x[a-fA-F0-9]{40}").unwrap(),
                Severity::Low,
                "Hardcoded address detected — verify this is intentional.".to_string(),
            ),
            (
                "REENTRANCY_PATTERN".to_string(),
                Regex::new(r"(call|delegatecall|staticcall)\s*\{[^}]*value:[^}]*\}[^;]*;[^}]*(?:balance|balances|user)").unwrap(),
                Severity::High,
                "Possible reentrancy: external call followed by state update.".to_string(),
            ),
            (
                "TX_DATA_LENGTH".to_string(),
                Regex::new(r"msg\.data\.length").unwrap(),
                Severity::Low,
                "Checking msg.data.length may break composability.".to_string(),
            ),
            (
                "CREATE2_SALT".to_string(),
                Regex::new(r"create2\s*\(").unwrap(),
                Severity::Medium,
                "CREATE2 usage — verify salt is not predictable.".to_string(),
            ),
            (
                "UNINITIALIZED_PROXY".to_string(),
                Regex::new(r"constructor\s*\(\s*\)").unwrap(),
                Severity::High,
                "Empty constructor in proxy pattern — ensure initialize() is protected.".to_string(),
            ),
        ]
    }

    pub async fn fetch_contract(&self, address: &str) -> Result<ContractInfo> {
        let url = format!(
            "{}?chainid={}&module=contract&action=getsourcecode&address={}&apikey={}",
            self.chain.api_url(),
            self.chain.chain_id(),
            address,
            self.api_key
        );

        let resp = self.client.get(&url).send().await
            .context("Failed to connect to block explorer API")?
            .json::<Value>().await
            .context("Failed to parse API response")?;

        if resp["status"].as_str() != Some("1") {
            let msg = resp["message"].as_str().unwrap_or("Unknown API error");
            return Err(anyhow::anyhow!("API Error: {}", msg));
        }

        let result = &resp["result"][0];
        let source_code      = result["SourceCode"].as_str().unwrap_or("").to_string();
        let contract_name    = result["ContractName"].as_str().unwrap_or("Unknown").to_string();
        let compiler         = result["CompilerType"].as_str().unwrap_or("Solidity").to_string();
        let compiler_version = result["CompilerVersion"].as_str().unwrap_or("unknown").to_string();
        let is_proxy         = result["Proxy"].as_str() == Some("1");
        let implementation   = result["Implementation"].as_str().map(|s| s.to_string());

        let sources = Self::parse_sources(&source_code, &contract_name);

        // لو ما في source code، نرجع contract بـ sources فارغة
        // عشان auto_hunter يقدر يعمل bytecode analysis
        if sources.is_empty() {
            return Ok(ContractInfo {
                address: address.to_string(),
                name: contract_name,
                compiler: compiler.clone(),
                compiler_version: String::new(),
                sources: vec![],
                is_proxy: false,
                implementation: None,
            });
        }

        Ok(ContractInfo {
            address: address.to_string(),
            name: contract_name,
            compiler,
            compiler_version,
            sources,
            is_proxy,
            implementation,
        })
    }

    fn parse_sources(source_code: &str, contract_name: &str) -> Vec<ContractSource> {
        let mut sources = Vec::new();

        if source_code.starts_with("{{") && source_code.ends_with("}}") {
            // Multi-file: {{ ... }} wrapping
            let inner = &source_code[1..source_code.len() - 1];
            if let Ok(parsed) = serde_json::from_str::<Value>(inner) {
                if let Some(obj) = parsed.get("sources").and_then(|s| s.as_object()) {
                    for (path, val) in obj {
                        if let Some(code) = val["content"].as_str() {
                            sources.push(ContractSource {
                                name: path.clone(),
                                content: code.to_string(),
                            });
                        }
                    }
                }
            }
        } else if source_code.starts_with('{') {
            // Single JSON object
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, Value>>(source_code) {
                for (path, val) in parsed {
                    let code = val.as_str()
                        .or_else(|| val["content"].as_str())
                        .unwrap_or("")
                        .to_string();
                    if !code.is_empty() {
                        sources.push(ContractSource { name: path, content: code });
                    }
                }
            }
        } else if !source_code.is_empty() {
            sources.push(ContractSource {
                name: format!("{}.sol", contract_name),
                content: source_code.to_string(),
            });
        }

        sources
    }

    pub fn pattern_scan(&self, contract: &ContractInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &contract.sources {
            for (id, regex, severity, description) in &self.patterns {
                for mat in regex.find_iter(&source.content) {
                    let start = mat.start();

                    // Extract line text safely
                    let line_start = source.content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
                    let line_end = source.content[start..]
                        .find('\n')
                        .map(|i| start + i)
                        .unwrap_or(source.content.len());
                    let line_text = source.content[line_start..line_end].trim().to_string();

                    // Skip comment lines
                    if line_text.starts_with("//")
                        || line_text.starts_with('*')
                        || line_text.starts_with("/*")
                    {
                        continue;
                    }

                    findings.push(Finding {
                        id: id.clone(),
                        severity: severity.clone(),
                        description: description.clone(),
                        file: source.name.clone(),
                        line: Self::get_line_number(&source.content, start),
                        line_text: Some(line_text),
                        position: start,
                        remediation: Self::get_remediation(id),
                        references: Self::get_references(id),
                    });
                }
            }
        }

        findings
    }

    fn get_line_number(content: &str, pos: usize) -> u32 {
        content[..pos].matches('\n').count() as u32 + 1
    }

    fn get_remediation(id: &str) -> Option<String> {
        match id {
            "TX_ORIGIN_AUTH"           => Some("Use msg.sender instead of tx.origin.".to_string()),
            "DELEGATECALL_UNCHECKED"   => Some("Whitelist delegatecall targets and check return values.".to_string()),
            "SELFDESTRUCT_ACCESS"      => Some("Remove selfdestruct or restrict behind access control with timelock.".to_string()),
            "UNSAFE_ERC20_TRANSFER"    => Some("Use Address.sendValue() or low-level call with reentrancy guards.".to_string()),
            "REENTRANCY_PATTERN"       => Some("Follow checks-effects-interactions or use ReentrancyGuard.".to_string()),
            "ECRECOVER_MALLEABILITY"   => Some("Use OpenZeppelin ECDSA.recover().".to_string()),
            "BLOCK_TIMESTAMP_DEPENDENCE" => Some("Use block.number for intervals or Chainlink VRF for randomness.".to_string()),
            _ => None,
        }
    }

    fn get_references(id: &str) -> Vec<String> {
        match id {
            "TX_ORIGIN_AUTH" => vec![
                "https://swcregistry.io/docs/SWC-115".to_string(),
                "https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin".to_string(),
            ],
            "DELEGATECALL_UNCHECKED" => vec![
                "https://swcregistry.io/docs/SWC-112".to_string(),
            ],
            "REENTRANCY_PATTERN" => vec![
                "https://swcregistry.io/docs/SWC-107".to_string(),
            ],
            "ECRECOVER_MALLEABILITY" => vec![
                "https://swcregistry.io/docs/SWC-117".to_string(),
                "https://eips.ethereum.org/EIPS/eip-2".to_string(),
            ],
            _ => Vec::new(),
        }
    }
}
