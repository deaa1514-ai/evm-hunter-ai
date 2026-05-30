use serde::{Serialize, Deserialize};
use std::fs;
use std::cmp::Ordering;
use crate::scanner::ContractInfo;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high"     => Severity::High,
            "medium"   => Severity::Medium,
            "info"     => Severity::Info,
            _          => Severity::Low,
        }
    }

    pub fn to_score(&self) -> u32 {
        match self {
            Severity::Critical => 4,
            Severity::High     => 3,
            Severity::Medium   => 2,
            Severity::Low      => 1,
            Severity::Info     => 0,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_score().cmp(&other.to_score())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_text: Option<String>,
    pub position: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReport {
    pub address: String,
    pub name: String,
    pub chain: String,
    pub compiler_version: String,
    pub is_proxy: bool,
    pub findings: Vec<Finding>,
    pub risk_score: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub generated_at: String,
    pub total_contracts: usize,
    pub total_findings: usize,
    pub contracts: Vec<ContractReport>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

pub struct ReportGenerator {
    contracts: Vec<ContractReport>,
    chain_name: String,
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self {
            contracts: Vec::new(),
            chain_name: "ethereum".to_string(),
        }
    }

    pub fn set_chain(&mut self, chain: &str) {
        self.chain_name = chain.to_string();
    }

    pub fn add_contract(&mut self, address: &str, contract: &ContractInfo, findings: Vec<Finding>) {
        let risk_score = findings.iter().map(|f| f.severity.to_score()).sum();
        self.contracts.push(ContractReport {
            address: address.to_string(),
            name: contract.name.clone(),
            chain: self.chain_name.clone(),
            compiler_version: contract.compiler_version.clone(),
            is_proxy: contract.is_proxy,
            findings,
            risk_score,
        });
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info = 0usize;

        for contract in &self.contracts {
            for finding in &contract.findings {
                match finding.severity {
                    Severity::Critical => critical += 1,
                    Severity::High     => high     += 1,
                    Severity::Medium   => medium   += 1,
                    Severity::Low      => low      += 1,
                    Severity::Info     => info     += 1,
                }
            }
        }

        let report = ScanReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_contracts: self.contracts.len(),
            total_findings: critical + high + medium + low + info,
            contracts: self.contracts.clone(),
            summary: ReportSummary {
                critical_count: critical,
                high_count: high,
                medium_count: medium,
                low_count: low,
                info_count: info,
            },
        };

        let json = serde_json::to_string_pretty(&report)?;
        fs::write(path, json)?;
        Ok(())
    }
}
