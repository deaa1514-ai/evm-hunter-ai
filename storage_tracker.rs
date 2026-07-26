//! Storage Tracking — يتتبع storage slots ويكتشف:
//! - Proxy takeover
//! - Storage collision  
//! - Upgrade bugs
//! - Uninitialized slots

use std::collections::HashMap;
use solang_parser::{parse, pt};
use crate::reporter::{Finding, Severity};

// ─── EIP-1967 Storage Slots ─────────────────────────

const EIP1967_IMPL_SLOT: &str = "360894a13ba1a3210667c828492db98dca3e2076635130ab13d8759af565";
const EIP1967_ADMIN_SLOT: &str = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const EIP1967_BEACON_SLOT: &str = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

#[derive(Debug, Clone)]
pub struct StorageSlot {
    pub name: String,
    pub slot_type: SlotType,
    pub line: u32,
    pub is_initialized: bool,
    pub can_be_overwritten: bool,
    pub written_by: Vec<String>,  // which functions write to this slot
}

#[derive(Debug, Clone, PartialEq)]
pub enum SlotType {
    EIP1967Implementation,
    EIP1967Admin,
    EIP1967Beacon,
    OwnerSlot,
    BalanceSlot,
    AllowanceSlot,
    CustomSlot(String),
}

#[derive(Debug, Clone)]
pub struct StorageCollision {
    pub slot1: String,
    pub slot2: String,
    pub description: String,
}

pub struct StorageTracker;

impl StorageTracker {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, sources: &[crate::scanner::ContractSource]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in sources {
            let slots = self.extract_slots(&source.content);
            findings.extend(self.detect_proxy_issues(&source.name, &source.content, &slots));
            findings.extend(self.detect_storage_collisions(&source.name, &slots));
            findings.extend(self.detect_uninitialized_upgradeable(&source.name, &source.content, &slots));
        }

        findings
    }

    fn extract_slots(&self, source: &str) -> Vec<StorageSlot> {
        let mut slots = Vec::new();
        let lower = source.to_lowercase();

        // EIP-1967 slots
        if lower.contains(EIP1967_IMPL_SLOT) || lower.contains("implementation") {
            slots.push(StorageSlot {
                name: "_implementation".to_string(),
                slot_type: SlotType::EIP1967Implementation,
                line: 0,
                is_initialized: lower.contains("_setimplementation") || lower.contains("upgradeto"),
                can_be_overwritten: !lower.contains("onlyproxy") && !lower.contains("onlyowner"),
                written_by: self.find_writers(source, "implementation"),
            });
        }

        if lower.contains(EIP1967_ADMIN_SLOT) || lower.contains("_admin") {
            slots.push(StorageSlot {
                name: "_admin".to_string(),
                slot_type: SlotType::EIP1967Admin,
                line: 0,
                is_initialized: lower.contains("_changeadmin") || lower.contains("admin()"),
                can_be_overwritten: !lower.contains("ifadmin") && !lower.contains("onlyadmin"),
                written_by: self.find_writers(source, "admin"),
            });
        }

        // Owner slot
        if lower.contains("owner") {
            slots.push(StorageSlot {
                name: "_owner".to_string(),
                slot_type: SlotType::OwnerSlot,
                line: 0,
                is_initialized: lower.contains("_owner = ") || lower.contains("owner = msg.sender"),
                can_be_overwritten: lower.contains("transferownership") && 
                    !lower.contains("onlyowner transferownership"),
                written_by: self.find_writers(source, "owner"),
            });
        }

        slots
    }

    fn find_writers(&self, source: &str, slot_name: &str) -> Vec<String> {
        let mut writers = Vec::new();
        let lower = source.to_lowercase();
        let slot_lower = slot_name.to_lowercase();

        // Find function names that write to this slot
        for line in source.lines() {
            if line.to_lowercase().contains(&format!("{} =", slot_lower)) 
               || line.to_lowercase().contains(&format!("_{} =", slot_lower)) {
                writers.push(line.trim().to_string());
            }
        }

        writers
    }

    fn detect_proxy_issues(&self, filename: &str, source: &str, slots: &[StorageSlot]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = source.to_lowercase();

        // Implementation slot قابل للكتابة بدون حماية
        for slot in slots {
            if slot.slot_type == SlotType::EIP1967Implementation && slot.can_be_overwritten {
                findings.push(Finding {
                    id: "STORAGE_PROXY_TAKEOVER".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "PROXY TAKEOVER RISK: Implementation slot can be overwritten — attacker can point proxy to malicious contract"
                    ),
                    file: filename.to_string(),
                    line: slot.line,
                    line_text: None,
                    position: 0,
                    remediation: Some("Protect upgradeTo() with onlyOwner/onlyAdmin and timelock".to_string()),
                    references: vec!["https://eips.ethereum.org/EIPS/eip-1967".to_string()],
                });
            }

            if slot.slot_type == SlotType::EIP1967Admin && !slot.is_initialized {
                findings.push(Finding {
                    id: "STORAGE_UNINITIALIZED_ADMIN".to_string(),
                    severity: Severity::Critical,
                    description: "Proxy admin slot not initialized — anyone can become admin!".to_string(),
                    file: filename.to_string(),
                    line: slot.line,
                    line_text: None,
                    position: 0,
                    remediation: Some("Initialize admin in constructor or initializer".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-118".to_string()],
                });
            }
        }

        // Storage collision بين proxy وimplementation
        if lower.contains("delegatecall") {
            let proxy_has_vars = lower.contains("uint256 private")
                || lower.contains("address private")
                || lower.contains("mapping(");

            if proxy_has_vars && lower.contains("delegatecall") {
                findings.push(Finding {
                    id: "STORAGE_COLLISION".to_string(),
                    severity: Severity::High,
                    description: "Potential storage collision: Proxy declares state variables that may overlap with implementation's storage layout".to_string(),
                    file: filename.to_string(),
                    line: 0,
                    line_text: None,
                    position: 0,
                    remediation: Some("Use EIP-1967 unstructured storage or ensure proxy has no state variables".to_string()),
                    references: vec!["https://blog.openzeppelin.com/proxy-patterns/".to_string()],
                });
            }
        }

        findings
    }

    fn detect_storage_collisions(&self, filename: &str, slots: &[StorageSlot]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // تحقق من تضارب بين الـ slots
        let impl_slot = slots.iter().find(|s| s.slot_type == SlotType::EIP1967Implementation);
        let admin_slot = slots.iter().find(|s| s.slot_type == SlotType::EIP1967Admin);
        let owner_slot = slots.iter().find(|s| s.slot_type == SlotType::OwnerSlot);

        // لو admin وowner في نفس الـ contract بدون EIP-1967
        if admin_slot.is_some() && owner_slot.is_some() && impl_slot.is_none() {
            findings.push(Finding {
                id: "STORAGE_DUAL_AUTHORITY".to_string(),
                severity: Severity::Medium,
                description: "Both admin and owner roles exist — verify they don't conflict or overlap in storage layout".to_string(),
                file: filename.to_string(),
                line: 0,
                line_text: None,
                position: 0,
                remediation: Some("Use role-based access control (OpenZeppelin AccessControl)".to_string()),
                references: vec![],
            });
        }

        findings
    }

    fn detect_uninitialized_upgradeable(&self, filename: &str, source: &str, slots: &[StorageSlot]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lower = source.to_lowercase();

        // Upgradeable contract بدون __gap
        let is_upgradeable = lower.contains("upgradeable") || lower.contains("uups") 
            || lower.contains("initializable");

        if is_upgradeable && !lower.contains("__gap") {
            findings.push(Finding {
                id: "STORAGE_NO_GAP".to_string(),
                severity: Severity::Medium,
                description: "Upgradeable contract missing storage gap (__gap) — future upgrades may cause storage collisions".to_string(),
                file: filename.to_string(),
                line: 0,
                line_text: None,
                position: 0,
                remediation: Some("Add: uint256[50] private __gap; at the end of storage variables".to_string()),
                references: vec!["https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps".to_string()],
            });
        }

        findings
    }
}
