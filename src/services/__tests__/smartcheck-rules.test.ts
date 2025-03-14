import { rules } from "../smartcheck-rules";

describe("SmartCheck Rules", () => {
  describe("Reentrancy Check", () => {
    it("should detect reentrancy vulnerability", () => {
      const code = `
        function withdraw(uint amount) {
          msg.sender.call{value: amount}("");
          balances[msg.sender] -= amount;
        }
      `;
      const result = rules[0].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("high");
      expect(result?.rule).toBe("reentrancy");
    });
  });

  describe("tx.origin Check", () => {
    it("should detect tx.origin usage", () => {
      const code = `
        function isOwner() returns (bool) {
          return tx.origin == owner;
        }
      `;
      const result = rules[1].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("high");
      expect(result?.rule).toBe("tx-origin");
    });

    it("should not detect msg.sender usage", () => {
      const code = `
        function isOwner() returns (bool) {
          return msg.sender == owner;
        }
      `;
      const result = rules[1].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Timestamp Dependence Check", () => {
    it("should detect block.timestamp usage", () => {
      const code = `
        function getCurrentTime() returns (uint) {
          return block.timestamp;
        }
      `;
      const result = rules[2].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("medium");
      expect(result?.rule).toBe("timestamp-dependence");
    });

    it("should not detect block.number usage", () => {
      const code = `
        function getCurrentBlock() returns (uint) {
          return block.number;
        }
      `;
      const result = rules[2].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Hardcoded Address Check", () => {
    it("should detect hardcoded Ethereum address", () => {
      const code = `
        address constant owner = 0x1234567890123456789012345678901234567890;
      `;
      const result = rules[3].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("medium");
      expect(result?.rule).toBe("hardcoded-address");
    });

    it("should not detect non-address hex values", () => {
      const code = `
        uint256 constant value = 0x1234;
      `;
      const result = rules[3].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Unchecked Send Check", () => {
    it("should detect unchecked send", () => {
      const code = `
        function sendEther(address to, uint amount) {
          to.send(amount);
        }
      `;
      const result = rules[4].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("medium");
      expect(result?.rule).toBe("unchecked-send");
    });

    it("should not detect checked send", () => {
      const code = `
        function sendEther(address to, uint amount) {
          require(to.send(amount), "Transfer failed");
        }
      `;
      const result = rules[4].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Delegatecall Usage Check", () => {
    it("should detect delegatecall usage", () => {
      const code = `
        function delegateCall(address target, bytes memory data) {
          target.delegatecall(data);
        }
      `;
      const result = rules[5].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("high");
      expect(result?.rule).toBe("delegatecall-usage");
    });

    it("should not detect regular call", () => {
      const code = `
        function call(address target, bytes memory data) {
          target.call(data);
        }
      `;
      const result = rules[5].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Selfdestruct Usage Check", () => {
    it("should detect selfdestruct usage", () => {
      const code = `
        function destroy() {
          selfdestruct(payable(owner));
        }
      `;
      const result = rules[6].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("high");
      expect(result?.rule).toBe("selfdestruct-usage");
    });

    it("should not detect other function calls", () => {
      const code = `
        function transfer(address to, uint amount) {
          to.transfer(amount);
        }
      `;
      const result = rules[6].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Suicide Usage Check", () => {
    it("should detect deprecated suicide usage", () => {
      const code = `
        function destroy() {
          suicide(owner);
        }
      `;
      const result = rules[7].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("high");
      expect(result?.rule).toBe("suicide-usage");
    });

    it("should not detect selfdestruct usage", () => {
      const code = `
        function destroy() {
          selfdestruct(payable(owner));
        }
      `;
      const result = rules[7].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Throw Usage Check", () => {
    it("should detect deprecated throw usage", () => {
      const code = `
        function validate(uint amount) {
          if (amount == 0) throw;
        }
      `;
      const result = rules[8].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("medium");
      expect(result?.rule).toBe("throw-usage");
    });

    it("should not detect require usage", () => {
      const code = `
        function validate(uint amount) {
          require(amount > 0, "Amount must be greater than 0");
        }
      `;
      const result = rules[8].check(code, 1);
      expect(result).toBeNull();
    });
  });

  describe("Gas Limit Check", () => {
    it("should detect potential gas limit issue in loop", () => {
      const code = `
        function processArray(uint[] memory items) {
          for (uint i = 0; i < items.length; i++) {
            processItem(items[i]);
          }
        }
      `;
      const result = rules[9].check(code, 1);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe("medium");
      expect(result?.rule).toBe("gas-limit");
    });

    it("should not detect loop with limit check", () => {
      const code = `
        function processArray(uint[] memory items) {
          require(items.length <= 100, "Array too large");
          for (uint i = 0; i < items.length; i++) {
            processItem(items[i]);
          }
        }
      `;
      const result = rules[9].check(code, 1);
      expect(result).toBeNull();
    });
  });
});
