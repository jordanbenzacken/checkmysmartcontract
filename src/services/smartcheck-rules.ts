import { SmartCheckResult } from "./smartcheck-service";

interface Rule {
  id: string;
  severity: "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
  check: (code: string, line: number) => SmartCheckResult | null;
}

export const rules: Rule[] = [
  {
    id: "reentrancy",
    severity: "high",
    description:
      "Potential reentrancy vulnerability detected. State changes are made after external calls.",
    recommendation:
      "Consider using the Checks-Effects-Interactions pattern or a reentrancy guard.",
    check: (code: string, line: number) => {
      const hasExternalCall =
        code.includes(".call{") ||
        code.includes(".send(") ||
        code.includes(".transfer(");
      const hasStateChange =
        code.includes("balances[") ||
        code.includes("+=") ||
        code.includes("-=");

      if (hasExternalCall && hasStateChange) {
        return {
          severity: "high",
          message: "Potential reentrancy vulnerability detected",
          line,
          column: 1,
          rule: "reentrancy",
          description:
            "The contract may be vulnerable to reentrancy attacks. State changes are made after external calls.",
          recommendation:
            "Consider using the Checks-Effects-Interactions pattern or a reentrancy guard.",
        };
      }
      return null;
    },
  },
  {
    id: "tx-origin",
    severity: "high",
    description:
      "Use of tx.origin for authentication is vulnerable to phishing attacks.",
    recommendation: "Use msg.sender instead of tx.origin for authentication.",
    check: (code: string, line: number) => {
      if (code.includes("tx.origin")) {
        return {
          severity: "high",
          message: "Use of tx.origin detected",
          line,
          column: 1,
          rule: "tx-origin",
          description:
            "Use of tx.origin for authentication is vulnerable to phishing attacks.",
          recommendation:
            "Use msg.sender instead of tx.origin for authentication.",
        };
      }
      return null;
    },
  },
  {
    id: "timestamp-dependence",
    severity: "medium",
    description: "Contract uses block.timestamp for critical operations.",
    recommendation:
      "Avoid using block.timestamp for critical operations as it can be manipulated by miners.",
    check: (code: string, line: number) => {
      if (code.includes("block.timestamp")) {
        return {
          severity: "medium",
          message: "Timestamp dependence detected",
          line,
          column: 1,
          rule: "timestamp-dependence",
          description: "Contract uses block.timestamp for critical operations.",
          recommendation:
            "Avoid using block.timestamp for critical operations as it can be manipulated by miners.",
        };
      }
      return null;
    },
  },
  {
    id: "hardcoded-address",
    severity: "medium",
    description: "Contract contains hardcoded Ethereum addresses.",
    recommendation:
      "Use configuration variables or constructor parameters instead of hardcoded addresses.",
    check: (code: string, line: number) => {
      const addressRegex = /0x[a-fA-F0-9]{40}/g;
      if (addressRegex.test(code)) {
        return {
          severity: "medium",
          message: "Hardcoded address detected",
          line,
          column: 1,
          rule: "hardcoded-address",
          description: "Contract contains hardcoded Ethereum addresses.",
          recommendation:
            "Use configuration variables or constructor parameters instead of hardcoded addresses.",
        };
      }
      return null;
    },
  },
  {
    id: "unchecked-send",
    severity: "medium",
    description: "Unchecked return value from send/transfer call.",
    recommendation: "Always check the return value of send/transfer calls.",
    check: (code: string, line: number) => {
      if (code.includes(".send(") || code.includes(".transfer(")) {
        const hasCheck =
          code.includes("require(") ||
          code.includes("if (") ||
          code.includes("assert(");
        if (!hasCheck) {
          return {
            severity: "medium",
            message: "Unchecked send/transfer detected",
            line,
            column: 1,
            rule: "unchecked-send",
            description: "Unchecked return value from send/transfer call.",
            recommendation:
              "Always check the return value of send/transfer calls.",
          };
        }
      }
      return null;
    },
  },
  {
    id: "delegatecall-usage",
    severity: "high",
    description: "Use of delegatecall detected.",
    recommendation:
      "Be extremely careful with delegatecall as it can lead to unexpected behavior and vulnerabilities.",
    check: (code: string, line: number) => {
      if (code.includes(".delegatecall(")) {
        return {
          severity: "high",
          message: "Use of delegatecall detected",
          line,
          column: 1,
          rule: "delegatecall-usage",
          description: "Use of delegatecall detected.",
          recommendation:
            "Be extremely careful with delegatecall as it can lead to unexpected behavior and vulnerabilities.",
        };
      }
      return null;
    },
  },
  {
    id: "selfdestruct-usage",
    severity: "high",
    description: "Use of selfdestruct detected.",
    recommendation:
      "Be careful with selfdestruct as it can lead to loss of funds.",
    check: (code: string, line: number) => {
      if (code.includes("selfdestruct(")) {
        return {
          severity: "high",
          message: "Use of selfdestruct detected",
          line,
          column: 1,
          rule: "selfdestruct-usage",
          description: "Use of selfdestruct detected.",
          recommendation:
            "Be careful with selfdestruct as it can lead to loss of funds.",
        };
      }
      return null;
    },
  },
  {
    id: "suicide-usage",
    severity: "high",
    description: "Use of deprecated suicide function detected.",
    recommendation: "Use selfdestruct instead of suicide as it is deprecated.",
    check: (code: string, line: number) => {
      if (code.includes("suicide(")) {
        return {
          severity: "high",
          message: "Use of deprecated suicide function detected",
          line,
          column: 1,
          rule: "suicide-usage",
          description: "Use of deprecated suicide function detected.",
          recommendation:
            "Use selfdestruct instead of suicide as it is deprecated.",
        };
      }
      return null;
    },
  },
  {
    id: "throw-usage",
    severity: "medium",
    description: "Use of deprecated throw statement detected.",
    recommendation: "Use require, assert, or revert instead of throw.",
    check: (code: string, line: number) => {
      if (code.includes("throw;")) {
        return {
          severity: "medium",
          message: "Use of deprecated throw statement detected",
          line,
          column: 1,
          rule: "throw-usage",
          description: "Use of deprecated throw statement detected.",
          recommendation: "Use require, assert, or revert instead of throw.",
        };
      }
      return null;
    },
  },
  {
    id: "gas-limit",
    severity: "medium",
    description: "Potential gas limit issue detected.",
    recommendation:
      "Consider using loops with a fixed number of iterations or implement pagination.",
    check: (code: string, line: number) => {
      if (code.includes("for (") || code.includes("while (")) {
        const hasLimit =
          code.includes("require(") ||
          code.includes("if (") ||
          code.includes("assert(");
        if (!hasLimit) {
          return {
            severity: "medium",
            message: "Potential gas limit issue detected",
            line,
            column: 1,
            rule: "gas-limit",
            description: "Potential gas limit issue detected.",
            recommendation:
              "Consider using loops with a fixed number of iterations or implement pagination.",
          };
        }
      }
      return null;
    },
  },
];
