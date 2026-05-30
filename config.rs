use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub etherscan_api_key: String,
    pub basescan_api_key: Option<String>,
    pub arbiscan_api_key: Option<String>,
    pub optimism_api_key: Option<String>,
    pub polygonscan_api_key: Option<String>,
    pub rpc_urls: RpcUrls,
    pub scanning: ScanConfig,
    pub reporting: ReportConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RpcUrls {
    pub ethereum: String,
    pub base: String,
    pub arbitrum: String,
    pub optimism: String,
    pub polygon: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanConfig {
    pub min_severity: String,
    pub max_depth: u32,
    pub enable_ast: bool,
    pub enable_regex: bool,
    pub enable_foundry_poc: bool,
    pub follow_proxies: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportConfig {
    pub format: String, // json, markdown, sarif
    pub include_code_snippets: bool,
    pub include_remediation: bool,
    pub include_references: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            etherscan_api_key: String::new(),
            basescan_api_key: None,
            arbiscan_api_key: None,
            optimism_api_key: None,
            polygonscan_api_key: None,
            rpc_urls: RpcUrls {
                ethereum: "https://eth.llamarpc.com".to_string(),
                base: "https://base.llamarpc.com".to_string(),
                arbitrum: "https://arb1.arbitrum.io/rpc".to_string(),
                optimism: "https://mainnet.optimism.io".to_string(),
                polygon: "https://polygon-rpc.com".to_string(),
            },
            scanning: ScanConfig {
                min_severity: "low".to_string(),
                max_depth: 3,
                enable_ast: true,
                enable_regex: true,
                enable_foundry_poc: false,
                follow_proxies: true,
            },
            reporting: ReportConfig {
                format: "json".to_string(),
                include_code_snippets: true,
                include_remediation: true,
                include_references: true,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        if Path::new(path).exists() {
            let content = fs::read_to_string(path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Config::default();
            let toml = toml::to_string_pretty(&config)?;
            fs::write(path, toml)?;
            Ok(config)
        }
    }

    pub fn get_api_key(&self, chain: &str) -> String {
        match chain {
            "ethereum" | "eth" | "mainnet" => self.etherscan_api_key.clone(),
            "base" => self.basescan_api_key.clone().unwrap_or_else(|| self.etherscan_api_key.clone()),
            "arbitrum" | "arb" => self.arbiscan_api_key.clone().unwrap_or_else(|| self.etherscan_api_key.clone()),
            "optimism" | "op" => self.optimism_api_key.clone().unwrap_or_else(|| self.etherscan_api_key.clone()),
            "polygon" | "matic" => self.polygonscan_api_key.clone().unwrap_or_else(|| self.etherscan_api_key.clone()),
            _ => self.etherscan_api_key.clone(),
        }
    }
}
