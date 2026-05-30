use solang_parser::pt;
use solang_parser::parse;
use crate::scanner::ContractInfo;
use crate::reporter::{Finding, Severity};

pub struct AstAnalyzer;

impl AstAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_contract(&self, contract: &ContractInfo) -> Vec<Finding> {
        let mut findings = Vec::new();
        for source in &contract.sources {
            match parse(&source.content, 0) {
                Ok((pt, _comments)) => {
                    findings.extend(self.analyze_pt(&source.name, &pt));
                }
                Err(e) => {
                    eprintln!("   ⚠️  AST parsing failed for {}: {:?}", source.name, e);
                }
            }
        }
        findings
    }

    pub fn analyze_source(&self, filename: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        match parse(content, 0) {
            Ok((pt, _comments)) => {
                findings.extend(self.analyze_pt(filename, &pt));
            }
            Err(e) => {
                eprintln!("   ⚠️  AST parsing failed for {}: {:?}", filename, e);
            }
        }
        findings
    }

    fn analyze_pt(&self, filename: &str, pt: &pt::SourceUnit) -> Vec<Finding> {
        let mut findings = Vec::new();
        for part in &pt.0 {
            match part {
                pt::SourceUnitPart::ContractDefinition(contract) => {
                    findings.extend(self.analyze_contract_def(filename, contract));
                }
                pt::SourceUnitPart::FunctionDefinition(func) => {
                    findings.extend(self.analyze_function(filename, func, None));
                }
                _ => {}
            }
        }
        findings
    }

    fn analyze_contract_def(&self, filename: &str, contract: &pt::ContractDefinition) -> Vec<Finding> {
        let mut findings = Vec::new();
        let contract_name = contract.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
        for part in &contract.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => {
                    findings.extend(self.analyze_function(filename, func, Some(&contract_name)));
                }
                pt::ContractPart::VariableDefinition(var) => {
                    findings.extend(self.analyze_variable(filename, var, &contract_name));
                }
                _ => {}
            }
        }
        findings
    }

    fn loc_to_offset(loc: &pt::Loc) -> u32 {
        match loc {
            pt::Loc::File(_, start, _) => *start as u32,
            _ => 0,
        }
    }

    fn analyze_function(
        &self,
        filename: &str,
        func: &pt::FunctionDefinition,
        contract_name: Option<&str>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name = func.name.as_ref().map(|n| n.name.clone())
            .unwrap_or_else(|| "constructor".to_string());

        let is_public_or_external = func.ty == pt::FunctionTy::Function
            && func.attributes.iter().any(|a| {
                matches!(
                    a,
                    pt::FunctionAttribute::Visibility(pt::Visibility::External(_))
                    | pt::FunctionAttribute::Visibility(pt::Visibility::Public(_))
                )
            });

        let has_modifier = func.attributes.iter().any(|a| {
            matches!(a, pt::FunctionAttribute::BaseOrModifier(_, _))
        });

        let is_view_or_pure = func.attributes.iter().any(|a| {
            matches!(
                a,
                pt::FunctionAttribute::Mutability(pt::Mutability::View(_))
                | pt::FunctionAttribute::Mutability(pt::Mutability::Pure(_))
            )
        });

        if is_public_or_external && !has_modifier && !is_view_or_pure {
            findings.push(Finding {
                id: "AST_UNPROTECTED_FUNCTION".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Function '{}' in contract '{}' is public/external with no modifiers.",
                    func_name,
                    contract_name.unwrap_or("Unknown")
                ),
                file: filename.to_string(),
                line: Self::loc_to_offset(&func.loc),
                line_text: None,
                position: 0,
                remediation: Some("Add access control modifiers (onlyOwner, auth, etc.).".to_string()),
                references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
            });
        }

        if let Some(body) = &func.body {
            let body_str = format!("{:?}", body);

            if body_str.contains("delegatecall") {
                findings.push(Finding {
                    id: "AST_DELEGATECALL_IN_FUNCTION".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Function '{}' contains delegatecall. Verify target address is strictly controlled.",
                        func_name
                    ),
                    file: filename.to_string(),
                    line: Self::loc_to_offset(&func.loc),
                    line_text: None,
                    position: 0,
                    remediation: Some("Whitelist delegatecall targets and verify return values.".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-112".to_string()],
                });
            }

            if body_str.contains("selfdestruct") {
                findings.push(Finding {
                    id: "AST_SELFDESTRUCT_IN_FUNCTION".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Function '{}' can selfdestruct the contract. Ensure strict access control.",
                        func_name
                    ),
                    file: filename.to_string(),
                    line: Self::loc_to_offset(&func.loc),
                    line_text: None,
                    position: 0,
                    remediation: Some("Add onlyOwner or multisig requirement for selfdestruct.".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-106".to_string()],
                });
            }

            if body_str.contains("call") && body_str.contains("value")
                && !body_str.contains("require") && !body_str.contains("success")
            {
                findings.push(Finding {
                    id: "AST_UNCHECKED_EXTERNAL_CALL".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Function '{}' performs external call with value but may not check return value.",
                        func_name
                    ),
                    file: filename.to_string(),
                    line: Self::loc_to_offset(&func.loc),
                    line_text: None,
                    position: 0,
                    remediation: Some(
                        r#"Always check return value: (bool success,) = addr.call{value: x}(""); require(success);"#
                            .to_string(),
                    ),
                    references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
                });
            }
        }

        findings
    }

    fn analyze_variable(
        &self,
        filename: &str,
        var: &pt::VariableDefinition,
        contract_name: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if var.initializer.is_none() {
            let ty_str = var.ty.to_string();
            if ty_str.contains("address") || ty_str.contains("uint") {
                findings.push(Finding {
                    id: "AST_UNINITIALIZED_STATE".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "State variable in contract '{}' is declared but not initialized.",
                        contract_name
                    ),
                    file: filename.to_string(),
                    line: Self::loc_to_offset(&var.loc),
                    line_text: None,
                    position: 0,
                    remediation: Some(
                        "Initialize state variables in constructor or declare as immutable."
                            .to_string(),
                    ),
                    references: Vec::new(),
                });
            }
        }

        findings
    }
}
