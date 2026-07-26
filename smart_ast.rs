//! Smart AST Engine — يفهم بنية العقد بعمق
//! يبني: CFG, Permission Model, Money Flow, Proxy Detection

use solang_parser::{parse, pt};
use std::collections::{HashMap, HashSet};
use crate::reporter::{Finding, Severity};
use crate::scanner::ContractSource;

// ─── Data Structures ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub name: String,
    pub visibility: Visibility,
    pub modifiers: Vec<String>,
    pub is_payable: bool,
    pub is_view: bool,
    pub calls: Vec<String>,          // دوال يستدعيها
    pub external_calls: Vec<ExternalCall>,
    pub state_changes: Vec<StateChange>,
    pub money_flows: Vec<MoneyFlow>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ExternalCall {
    pub call_type: CallType,
    pub target: String,        // address أو variable name
    pub target_controlled_by: TargetControl,
    pub value_sent: bool,
    pub return_checked: bool,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallType {
    Call,
    DelegateCall,
    StaticCall,
    Transfer,
    Send,
    FunctionCall,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetControl {
    Immutable,        // hardcoded address
    OwnerControlled,  // owner يتحكم فيه
    UserControlled,   // المستخدم يتحكم فيه — خطر!
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StateChange {
    pub variable: String,
    pub change_type: ChangeType,
    pub before_external_call: bool,   // هل يتغير قبل أم بعد external call?
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Increase,
    Decrease,
    Assign,
    Delete,
}

#[derive(Debug, Clone)]
pub struct MoneyFlow {
    pub direction: FlowDirection,
    pub amount: String,
    pub to: String,
    pub guarded: bool,    // هل محمي بـ require/check؟
}

#[derive(Debug, Clone)]
pub enum FlowDirection {
    In,   // ETH يدخل
    Out,  // ETH يخرج
    TokenIn,
    TokenOut,
}

#[derive(Debug, Clone)]
pub struct PermissionModel {
    pub roles: HashMap<String, Vec<String>>,  // role → [functions]
    pub public_functions: Vec<String>,
    pub owner_functions: Vec<String>,
    pub unprotected_state_changers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContractGraph {
    pub name: String,
    pub functions: HashMap<String, FunctionNode>,
    pub permission_model: PermissionModel,
    pub is_proxy: bool,
    pub proxy_type: Option<ProxyType>,
    pub storage_vars: Vec<StorageVar>,
    pub inheritance: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ProxyType {
    EIP1967,
    UUPS,
    Transparent,
    Diamond,
    MinimalProxy,
    Custom,
}

#[derive(Debug, Clone)]
pub struct StorageVar {
    pub name: String,
    pub var_type: String,
    pub initialized: bool,
    pub line: u32,
}

// ─── Smart AST Analyzer ────────────────────────────────────

pub struct SmartAstEngine;

impl SmartAstEngine {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, sources: &[ContractSource]) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for source in sources {
            match parse(&source.content, 0) {
                Ok((pt, _)) => {
                    let graphs = self.build_contract_graphs(&source.name, &source.content, &pt);
                    for graph in &graphs {
                        all_findings.extend(self.analyze_graph(&source.name, graph, &source.content));
                    }
                }
                Err(_) => {}
            }
        }

        all_findings
    }

    fn build_contract_graphs(&self, _filename: &str, source: &str, pt: &pt::SourceUnit) -> Vec<ContractGraph> {
        let mut graphs = Vec::new();

        for part in &pt.0 {
            if let pt::SourceUnitPart::ContractDefinition(contract) = part {
                let name = contract.name.as_ref()
                    .map(|n| n.name.clone())
                    .unwrap_or_default();

                let mut graph = ContractGraph {
                    name: name.clone(),
                    functions: HashMap::new(),
                    permission_model: PermissionModel {
                        roles: HashMap::new(),
                        public_functions: Vec::new(),
                        owner_functions: Vec::new(),
                        unprotected_state_changers: Vec::new(),
                    },
                    is_proxy: false,
                    proxy_type: None,
                    storage_vars: Vec::new(),
                    inheritance: contract.base.iter()
                        .map(|b| b.name.identifiers.first()
                            .map(|i| i.name.clone())
                            .unwrap_or_default())
                        .collect(),
                };

                // Detect proxy type
                graph.is_proxy = self.detect_proxy(source, &graph.inheritance);
                graph.proxy_type = self.detect_proxy_type(source);

                // Build function nodes
                for part in &contract.parts {
                    match part {
                        pt::ContractPart::FunctionDefinition(func) => {
                            let node = self.build_function_node(func, source);
                            if let Some(n) = node {
                                graph.functions.insert(n.name.clone(), n);
                            }
                        }
                        pt::ContractPart::VariableDefinition(var) => {
                            let sv = StorageVar {
                                name: var.name.as_ref().map(|n| n.name.clone()).unwrap_or_default(),
                                var_type: format!("{:?}", var.ty),
                                initialized: var.initializer.is_some(),
                                line: Self::loc_line(&var.loc),
                            };
                            graph.storage_vars.push(sv);
                        }
                        _ => {}
                    }
                }

                // Build permission model
                graph.permission_model = self.build_permission_model(&graph.functions);

                graphs.push(graph);
            }
        }

        graphs
    }

    fn build_function_node(&self, func: &pt::FunctionDefinition, source: &str) -> Option<FunctionNode> {
        let name = func.name.as_ref()?.name.clone();

        let visibility = func.attributes.iter().find_map(|a| match a {
            pt::FunctionAttribute::Visibility(v) => Some(match v {
                pt::Visibility::Public(_) => Visibility::Public,
                pt::Visibility::External(_) => Visibility::External,
                pt::Visibility::Internal(_) => Visibility::Internal,
                pt::Visibility::Private(_) => Visibility::Private,
            }),
            _ => None,
        }).unwrap_or(Visibility::Unknown);

        let modifiers: Vec<String> = func.attributes.iter().filter_map(|a| {
            if let pt::FunctionAttribute::BaseOrModifier(_, base) = a {
                Some(base.name.identifiers.first()?.name.clone())
            } else { None }
        }).collect();

        let is_payable = func.attributes.iter().any(|a|
            matches!(a, pt::FunctionAttribute::Mutability(pt::Mutability::Payable(_)))
        );

        let is_view = func.attributes.iter().any(|a|
            matches!(a, pt::FunctionAttribute::Mutability(pt::Mutability::View(_) | pt::Mutability::Pure(_)))
        );

        let body_str = func.body.as_ref().map(|b| format!("{:?}", b)).unwrap_or_default();

        // Analyze body for patterns
        let external_calls = self.detect_external_calls(&body_str, source, Self::loc_line(&func.loc));
        let state_changes = self.detect_state_changes(&body_str, &external_calls);
        let money_flows = self.detect_money_flows(&body_str, is_payable);

        Some(FunctionNode {
            name,
            visibility,
            modifiers,
            is_payable,
            is_view,
            calls: self.extract_function_calls(&body_str),
            external_calls,
            state_changes,
            money_flows,
            line: Self::loc_line(&func.loc),
        })
    }

    fn detect_external_calls(&self, body: &str, _source: &str, base_line: u32) -> Vec<ExternalCall> {
        let mut calls = Vec::new();
        let lower = body.to_lowercase();

        if lower.contains("delegatecall") {
            let target_controlled = if lower.contains("_impl") || lower.contains("implementation") {
                if lower.contains("immutable") { TargetControl::Immutable }
                else { TargetControl::OwnerControlled }
            } else if lower.contains("addr") || lower.contains("target") {
                TargetControl::UserControlled
            } else {
                TargetControl::Unknown
            };

            calls.push(ExternalCall {
                call_type: CallType::DelegateCall,
                target: "unknown".to_string(),
                target_controlled_by: target_controlled,
                value_sent: false,
                return_checked: lower.contains("require") || lower.contains("success"),
                line: base_line,
            });
        }

        if lower.contains(".call{value:") || lower.contains(".call{value :") {
            calls.push(ExternalCall {
                call_type: CallType::Call,
                target: "unknown".to_string(),
                target_controlled_by: TargetControl::Unknown,
                value_sent: true,
                return_checked: lower.contains("require(success") || lower.contains("if (!success"),
                line: base_line,
            });
        }

        if lower.contains(".transfer(") {
            calls.push(ExternalCall {
                call_type: CallType::Transfer,
                target: "unknown".to_string(),
                target_controlled_by: TargetControl::Unknown,
                value_sent: true,
                return_checked: true, // transfer يرفع exception تلقائياً
                line: base_line,
            });
        }

        calls
    }

    fn detect_state_changes(&self, body: &str, external_calls: &[ExternalCall]) -> Vec<StateChange> {
        let mut changes = Vec::new();
        let has_external = !external_calls.is_empty();

        for line in body.lines() {
            let lower = line.to_lowercase();
            if lower.contains("balance") || lower.contains("_balances") {
                if lower.contains("+=") || lower.contains("-=") || lower.contains("= ") {
                    changes.push(StateChange {
                        variable: "balance".to_string(),
                        change_type: if lower.contains("+=") { ChangeType::Increase } else { ChangeType::Decrease },
                        before_external_call: !has_external,
                    });
                }
            }
        }

        changes
    }

    fn detect_money_flows(&self, body: &str, is_payable: bool) -> Vec<MoneyFlow> {
        let mut flows = Vec::new();
        let lower = body.to_lowercase();

        if is_payable {
            flows.push(MoneyFlow {
                direction: FlowDirection::In,
                amount: "msg.value".to_string(),
                to: "contract".to_string(),
                guarded: lower.contains("require") || lower.contains("if"),
            });
        }

        if lower.contains("call{value:") || lower.contains(".transfer(") || lower.contains(".send(") {
            flows.push(MoneyFlow {
                direction: FlowDirection::Out,
                amount: "variable".to_string(),
                to: "external".to_string(),
                guarded: lower.contains("require") || lower.contains("onlyowner"),
            });
        }

        flows
    }

    fn extract_function_calls(&self, body: &str) -> Vec<String> {
        // Simple extraction of function call names
        let mut calls = Vec::new();
        for word in body.split_whitespace() {
            if word.ends_with('(') && !word.starts_with("if") && !word.starts_with("for") {
                calls.push(word.trim_end_matches('(').to_string());
            }
        }
        calls
    }

    fn build_permission_model(&self, functions: &HashMap<String, FunctionNode>) -> PermissionModel {
        let mut model = PermissionModel {
            roles: HashMap::new(),
            public_functions: Vec::new(),
            owner_functions: Vec::new(),
            unprotected_state_changers: Vec::new(),
        };

        for (name, func) in functions {
            let is_public = matches!(func.visibility, Visibility::Public | Visibility::External);

            if is_public {
                model.public_functions.push(name.clone());

                let has_access_control = func.modifiers.iter().any(|m| {
                    let ml = m.to_lowercase();
                    ml.contains("owner") || ml.contains("auth") || ml.contains("admin")
                    || ml.contains("only") || ml.contains("role") || ml.contains("guard")
                });

                if func.modifiers.iter().any(|m| m.to_lowercase().contains("owner")) {
                    model.owner_functions.push(name.clone());
                    model.roles.entry("owner".to_string())
                        .or_default()
                        .push(name.clone());
                }

                // دالة عامة بدون access control وتغير الحالة
                if !has_access_control && !func.is_view && !func.state_changes.is_empty() {
                    model.unprotected_state_changers.push(name.clone());
                }
            }
        }

        model
    }

    fn detect_proxy(&self, source: &str, inheritance: &[String]) -> bool {
        let lower = source.to_lowercase();
        lower.contains("delegatecall") ||
        inheritance.iter().any(|i| {
            let il = i.to_lowercase();
            il.contains("proxy") || il.contains("upgradeable") || il.contains("uups")
        })
    }

    fn detect_proxy_type(&self, source: &str) -> Option<ProxyType> {
        let lower = source.to_lowercase();
        if lower.contains("0x360894a13ba1a3210667c828492db98dca3e2076635130ab13d8759af565") {
            Some(ProxyType::EIP1967)
        } else if lower.contains("uups") || lower.contains("upgradeto") {
            Some(ProxyType::UUPS)
        } else if lower.contains("transparent") {
            Some(ProxyType::Transparent)
        } else if lower.contains("diamond") || lower.contains("facet") {
            Some(ProxyType::Diamond)
        } else if lower.contains("delegatecall") {
            Some(ProxyType::Custom)
        } else {
            None
        }
    }

    fn loc_line(loc: &pt::Loc) -> u32 {
        match loc {
            pt::Loc::File(_, start, _) => *start as u32,
            _ => 0,
        }
    }

    // ─── Graph Analysis → Findings ─────────────────────────

    fn analyze_graph(&self, filename: &str, graph: &ContractGraph, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        findings.extend(self.detect_dangerous_delegatecall(filename, graph));
        findings.extend(self.detect_reentrancy_by_flow(filename, graph));
        findings.extend(self.detect_unprotected_money_drain(filename, graph));
        findings.extend(self.detect_proxy_issues(filename, graph));
        findings.extend(self.detect_permission_escalation(filename, graph));
        findings.extend(self.detect_uncapped_minting(filename, graph, source));

        findings
    }

    fn detect_dangerous_delegatecall(&self, filename: &str, graph: &ContractGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (name, func) in &graph.functions {
            for call in &func.external_calls {
                if call.call_type == CallType::DelegateCall {
                    let (severity, description) = match &call.target_controlled_by {
                        TargetControl::UserControlled => (
                            Severity::Critical,
                            format!("DANGEROUS: delegatecall in '{}' with USER-CONTROLLED target — attacker can execute arbitrary code and drain contract", name)
                        ),
                        TargetControl::OwnerControlled => (
                            Severity::High,
                            format!("delegatecall in '{}' with owner-controlled target — risk of malicious upgrade", name)
                        ),
                        TargetControl::Immutable => (
                            Severity::Info,
                            format!("delegatecall in '{}' with immutable target — likely safe proxy pattern", name)
                        ),
                        TargetControl::Unknown => (
                            Severity::High,
                            format!("delegatecall in '{}' — verify target address control", name)
                        ),
                    };

                    if severity != Severity::Info {
                        findings.push(Finding {
                            id: "SMART_DELEGATECALL".to_string(),
                            severity,
                            description,
                            file: filename.to_string(),
                            line: func.line,
                            line_text: None,
                            position: 0,
                            remediation: Some("Whitelist delegatecall targets using immutable addresses".to_string()),
                            references: vec!["https://swcregistry.io/docs/SWC-112".to_string()],
                        });
                    }
                }
            }
        }

        findings
    }

    fn detect_reentrancy_by_flow(&self, filename: &str, graph: &ContractGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (name, func) in &graph.functions {
            let has_external_call = func.external_calls.iter().any(|c|
                matches!(c.call_type, CallType::Call | CallType::Transfer | CallType::Send) && c.value_sent
            );

            let has_state_after_call = func.state_changes.iter().any(|s| !s.before_external_call);

            if has_external_call && has_state_after_call {
                findings.push(Finding {
                    id: "SMART_REENTRANCY".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "REENTRANCY: '{}' sends ETH externally then updates state — classic reentrancy pattern",
                        name
                    ),
                    file: filename.to_string(),
                    line: func.line,
                    line_text: None,
                    position: 0,
                    remediation: Some("Use checks-effects-interactions pattern or ReentrancyGuard".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
                });
            }
        }

        findings
    }

    fn detect_unprotected_money_drain(&self, filename: &str, graph: &ContractGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for name in &graph.permission_model.unprotected_state_changers {
            if let Some(func) = graph.functions.get(name) {
                let drains_money = func.money_flows.iter().any(|f|
                    matches!(f.direction, FlowDirection::Out) && !f.guarded
                );

                if drains_money {
                    findings.push(Finding {
                        id: "SMART_UNPROTECTED_DRAIN".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "CRITICAL: '{}' is publicly accessible AND drains ETH/tokens WITHOUT access control",
                            name
                        ),
                        file: filename.to_string(),
                        line: func.line,
                        line_text: None,
                        position: 0,
                        remediation: Some("Add onlyOwner or equivalent access control".to_string()),
                        references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                    });
                }
            }
        }

        findings
    }

    fn detect_proxy_issues(&self, filename: &str, graph: &ContractGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !graph.is_proxy { return findings; }

        // Proxy بدون initialize محمي
        let has_initializer = graph.functions.contains_key("initialize") ||
                              graph.functions.contains_key("init");

        let initializer_protected = graph.functions.get("initialize")
            .or_else(|| graph.functions.get("init"))
            .map(|f| !f.modifiers.is_empty())
            .unwrap_or(false);

        if !has_initializer {
            findings.push(Finding {
                id: "SMART_PROXY_NO_INIT".to_string(),
                severity: Severity::High,
                description: format!(
                    "Proxy contract '{}' has no initialize() function — may be uninitialized",
                    graph.name
                ),
                file: filename.to_string(),
                line: 1,
                line_text: None,
                position: 0,
                remediation: Some("Add initialize() with initializer modifier from OpenZeppelin".to_string()),
                references: vec!["https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable".to_string()],
            });
        } else if !initializer_protected {
            findings.push(Finding {
                id: "SMART_PROXY_UNPROTECTED_INIT".to_string(),
                severity: Severity::Critical,
                description: format!(
                    "Proxy '{}': initialize() exists but NOT protected — anyone can reinitialize and take ownership!",
                    graph.name
                ),
                file: filename.to_string(),
                line: graph.functions.get("initialize").map(|f| f.line).unwrap_or(0),
                line_text: None,
                position: 0,
                remediation: Some("Add initializer modifier: function initialize() external initializer { ... }".to_string()),
                references: vec!["https://swcregistry.io/docs/SWC-118".to_string()],
            });
        }

        findings
    }

    fn detect_permission_escalation(&self, filename: &str, graph: &ContractGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        // دالة عامة تقدر تغير الـ owner أو الـ admin
        for (name, func) in &graph.functions {
            let is_public = matches!(func.visibility, Visibility::Public | Visibility::External);
            let changes_ownership = func.name.to_lowercase().contains("owner") ||
                                   func.name.to_lowercase().contains("admin") ||
                                   func.name.to_lowercase().contains("role");
            let unprotected = func.modifiers.is_empty();

            if is_public && changes_ownership && unprotected && !func.is_view {
                findings.push(Finding {
                    id: "SMART_PERMISSION_ESCALATION".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "PRIVILEGE ESCALATION: '{}' can modify ownership/roles without access control — anyone can become owner!",
                        name
                    ),
                    file: filename.to_string(),
                    line: func.line,
                    line_text: None,
                    position: 0,
                    remediation: Some("Add onlyOwner or role-based access control".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                });
            }
        }

        findings
    }

    fn detect_uncapped_minting(&self, filename: &str, graph: &ContractGraph, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = source.to_lowercase();

        for (name, func) in &graph.functions {
            let is_public = matches!(func.visibility, Visibility::Public | Visibility::External);
            let is_mint = func.name.to_lowercase().contains("mint") ||
                         func.calls.iter().any(|c| c.to_lowercase().contains("_mint"));
            let unprotected = func.modifiers.is_empty();

            if is_public && is_mint && unprotected && !func.is_view {
                // هل في حد أقصى للـ supply؟
                let has_cap = lower.contains("maxsupply") || lower.contains("max_supply") ||
                             lower.contains("cap") || lower.contains("require") && lower.contains("totalsupply");

                findings.push(Finding {
                    id: "SMART_UNCAPPED_MINT".to_string(),
                    severity: if has_cap { Severity::Medium } else { Severity::Critical },
                    description: format!(
                        "{} UNCAPPED MINT: '{}' allows anyone to mint tokens{}",
                        if has_cap { "⚠️" } else { "🚨" },
                        name,
                        if has_cap { " (has supply cap)" } else { " with NO supply limit — infinite inflation!" }
                    ),
                    file: filename.to_string(),
                    line: func.line,
                    line_text: None,
                    position: 0,
                    remediation: Some("Add onlyOwner/minter role AND maxSupply cap".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                });
            }
        }

        findings
    }
}
