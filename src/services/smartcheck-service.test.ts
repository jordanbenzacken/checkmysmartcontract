import { analyzeContract } from "./smartcheck-service";

describe("SmartCheck Service", () => {
  describe("analyzeContract", () => {
    it("should handle empty input", async () => {
      const results = await analyzeContract("");
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("Invalid source code provided");
    });

    it("should handle invalid input type", async () => {
      // @ts-ignore - Testing invalid input
      const results = await analyzeContract(null);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("Invalid source code provided");
    });

    it("should detect missing contract declaration", async () => {
      const code = `
        pragma solidity ^0.8.0;
        uint public value;
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("error");
      expect(results[0].message).toBe("No contract declaration found");
    });

    it("should detect public state variable without getter", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint public value;
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("low");
      expect(results[0].message).toBe("Public state variable without getter");
    });

    it("should not flag constant public state variables", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint public constant value = 100;
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("info");
      expect(results[0].message).toBe("No issues found");
    });

    it.skip("should detect reentrancy vulnerability", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Vulnerable {
          mapping(address => uint) public balances;
          
          function withdraw(uint amount) public {
            (bool success,) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(2); // Reentrancy + public state variable
      expect(results[0].severity).toBe("high");
      expect(results[0].message).toBe(
        "Potential reentrancy vulnerability detected"
      );
    });

    it("should detect public function without state mutability", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          function test() public {
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("medium");
      expect(results[0].message).toBe(
        "Public function without state mutability specifier"
      );
    });

    it.skip("should detect payable function without value validation", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          function deposit() public payable {
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("medium");
      expect(results[0].message).toBe(
        "Payable function without value validation"
      );
    });

    it.skip("should not flag payable function with value validation", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          function deposit() public payable {
            require(msg.value > 0);
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("info");
      expect(results[0].message).toBe("No issues found");
    });

    it("should handle multiple functions in a contract", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint public value;
          
          function deposit() public payable {
            // some code
          }
          
          function withdraw() public {
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results.length).toBeGreaterThan(1);
      expect(results.some((r) => r.severity === "low")).toBe(true); // Public state variable
      expect(results.some((r) => r.severity === "medium")).toBe(true); // Payable function without validation
    });

    it.skip("should handle contract with no issues", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint private value;
          
          function deposit() public payable {
            require(msg.value > 0);
            // some code
          }
          
          function withdraw() public pure {
            // some code
          }
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("info");
      expect(results[0].message).toBe("No issues found");
    });

    it("should handle different line endings", async () => {
      const code =
        "pragma solidity ^0.8.0;\r\ncontract Test {\r\n  uint public value;\r\n}";
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("low");
      expect(results[0].message).toBe("Public state variable without getter");
    });

    it("should handle tabs and extra spaces", async () => {
      const code = `
        pragma solidity ^0.8.0;
        contract Test {
          uint    public    value;
        }
      `;
      const results = await analyzeContract(code);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe("low");
      expect(results[0].message).toBe("Public state variable without getter");
    });
  });
});
