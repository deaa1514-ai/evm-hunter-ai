//! Control Flow Graph + Dataflow Analysis
//! يتتبع مسار البيانات من المدخلات للمخرجات

use std::collections::{HashMap, HashSet};
use solang_parser::{parse, pt};

// ─── CFG Node ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CfgNode {
    pub id: usize,
    pub kind: NodeKind,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub defs: HashSet<String>,    // variables defined here
    pub uses: HashSet<String>,    // variables used here
    pub taint: HashSet<String>,   // tainted (user-controlled) values
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeKind {
    Entry,
    Exit,
    Statement(String),
    Condition(String),
    ExternalCall { target: String, value: bool },
    StateWrite { variable: String },
    StateRead  { variable: String },
    Return,
}

// ─── Dataflow Facts ─────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DataflowFacts {
    /// user-controlled variables (msg.sender, msg.value, calldata)
    pub tainted: HashSet<String>,
    /// variables that affect ETH transfers
    pub controls_funds: HashSet<String>,
    /// variables that affect access control
    pub controls_auth: HashSet<String>,
    /// state changes that happen after external calls (reentrancy risk)
    pub post_call_writes: Vec<String>,
    /// paths from user input to sensitive operations
    pub taint_paths: Vec<TaintPath>,
}

#[derive(Debug, Clone)]
pub struct TaintPath {
    pub source: String,       // msg.sender, msg.value, etc.
    pub sink: String,         // ETH transfer, mint, etc.
    pub path: Vec<String>,    // intermediate steps
    pub is_dangerous: bool,
}

// ─── CFG Builder ────────────────────────────────────

pub struct CfgBuilder;

impl CfgBuilder {
    pub fn new() -> Self { Self }

    pub fn analyze_source(&self, source: &str) -> Vec<FunctionCfg> {
        let mut results = Vec::new();

        match parse(source, 0) {
            Ok((pt, _)) => {
                for part in &pt.0 {
                    if let pt::SourceUnitPart::ContractDefinition(contract) = part {
                        for cp in &contract.parts {
                            if let pt::ContractPart::FunctionDefinition(func) = cp {
                                if let Some(cfg) = self.build_function_cfg(func, source) {
                                    results.push(cfg);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        results
    }

    fn build_function_cfg(&self, func: &pt::FunctionDefinition, _source: &str) -> Option<FunctionCfg> {
        let name = func.name.as_ref()?.name.clone();
        let body_str = func.body.as_ref().map(|b| format!("{:?}", b)).unwrap_or_default();

        let facts = self.analyze_dataflow(&name, &body_str, func);

        Some(FunctionCfg {
            name,
            facts,
            has_reentrancy_risk: false,
            has_tainted_auth: false,
            has_tainted_funds: false,
        })
    }

    fn analyze_dataflow(&self, _name: &str, body: &str, func: &pt::FunctionDefinition) -> DataflowFacts {
        let mut facts = DataflowFacts::default();
        let lower = body.to_lowercase();

        // Seed taint sources
        if lower.contains("msg.sender") { facts.tainted.insert("msg.sender".to_string()); }
        if lower.contains("msg.value")  { facts.tainted.insert("msg.value".to_string()); }
        if lower.contains("calldata")   { facts.tainted.insert("calldata".to_string()); }
        if lower.contains("tx.origin")  { facts.tainted.insert("tx.origin".to_string()); }

        // Check if tainted values reach sensitive sinks
        let has_eth_transfer = lower.contains(".call{value:") 
            || lower.contains(".transfer(")
            || lower.contains(".send(");

        let has_mint = lower.contains("_mint(") 
            || lower.contains("mint(")
            || lower.contains("_totalsupply");

        let has_state_write = lower.contains(" = ") && !lower.contains("==");

        // Check for reentrancy pattern: external call THEN state write
        let call_pos = lower.find(".call{").or_else(|| lower.find(".transfer(")).unwrap_or(usize::MAX);
        let write_pos = lower.rfind(" = ").unwrap_or(0);

        if call_pos < write_pos && has_eth_transfer {
            facts.post_call_writes.push("balance/state".to_string());
        }

        // Build taint paths
        for taint_src in &facts.tainted.clone() {
            if has_eth_transfer {
                facts.taint_paths.push(TaintPath {
                    source: taint_src.clone(),
                    sink: "ETH_TRANSFER".to_string(),
                    path: vec!["function_body".to_string()],
                    is_dangerous: true,
                });
                facts.controls_funds.insert(taint_src.clone());
            }

            if has_mint {
                facts.taint_paths.push(TaintPath {
                    source: taint_src.clone(),
                    sink: "MINT".to_string(),
                    path: vec!["function_body".to_string()],
                    is_dangerous: true,
                });
            }
        }

        // Check access control
        let is_payable = func.attributes.iter().any(|a|
            matches!(a, pt::FunctionAttribute::Mutability(pt::Mutability::Payable(_)))
        );

        let has_modifier = !func.attributes.iter().filter_map(|a| {
            if let pt::FunctionAttribute::BaseOrModifier(_, b) = a {
                Some(b.name.identifiers.first()?.name.clone())
            } else { None }
        }).collect::<Vec<_>>().is_empty();

        if is_payable && !has_modifier {
            facts.controls_funds.insert("payable_unguarded".to_string());
        }

        facts
    }
}

#[derive(Debug, Clone)]
pub struct FunctionCfg {
    pub name: String,
    pub facts: DataflowFacts,
    pub has_reentrancy_risk: bool,
    pub has_tainted_auth: bool,
    pub has_tainted_funds: bool,
}

impl FunctionCfg {
    pub fn risk_score(&self) -> u32 {
        let mut score = 0;
        if !self.facts.post_call_writes.is_empty() { score += 40; } // reentrancy
        if !self.facts.controls_funds.is_empty()   { score += 30; } // fund control
        if self.facts.taint_paths.iter().any(|p| p.is_dangerous) { score += 20; }
        if self.facts.tainted.contains("tx.origin") { score += 10; } // tx.origin auth
        score
    }
}
