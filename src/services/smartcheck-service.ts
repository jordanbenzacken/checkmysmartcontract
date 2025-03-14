import { supabase } from "../lib/supabase";
import { rules } from "./smartcheck-rules";

export interface SmartCheckResult {
  severity: "high" | "medium" | "low" | "info" | "error";
  message: string;
  line: number;
  column: number;
  rule: string;
  description: string;
  recommendation: string;
}

function preprocessSolidityCode(code: string): string {
  return code
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\t/g, "    ")
    .trim();
}

function analyzeContractSimple(code: string): SmartCheckResult[] {
  const results: SmartCheckResult[] = [];
  const lines = code.split("\n").map((line) => line.trim());

  // Find contract declaration
  const contractLine = lines.findIndex((line) => line.startsWith("contract"));
  if (contractLine === -1) {
    return [
      {
        severity: "error",
        message: "No contract declaration found",
        line: 1,
        column: 1,
        rule: "syntax",
        description: "The code must contain a contract declaration.",
        recommendation:
          "Add a contract declaration using 'contract ContractName {'",
      },
    ];
  }

  // Find state variables
  const firstFunctionLine = lines.findIndex(
    (line, index) => index > contractLine && line.startsWith("function")
  );

  // Check state variables
  const stateVariables = lines.slice(contractLine + 1, firstFunctionLine);
  stateVariables.forEach((line, index) => {
    if (
      line.includes("public") &&
      !line.includes("constant") &&
      !line.includes("immutable")
    ) {
      results.push({
        severity: "low",
        message: "Public state variable without getter",
        line: contractLine + index + 2,
        column: 1,
        rule: "state-visibility",
        description:
          "Public state variables automatically create getters, which may expose sensitive data.",
        recommendation:
          "Consider using private visibility with explicit getter functions for better control.",
      });
    }
  });

  // Track function state
  let currentFunction: {
    code: string;
    hasExternalCall: boolean;
    hasStateChange: boolean;
    isPayable: boolean;
    visibility: "public" | "private" | "internal" | "external" | undefined;
    hasModifier: boolean;
    modifiers: string[];
  } | null = null;

  let functionStartLine = 0;

  // Second pass: Analyze functions and vulnerabilities
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("function")) {
      if (currentFunction) {
        analyzeFunction(currentFunction, functionStartLine, results);
      }

      const visibility = line.includes("public")
        ? ("public" as const)
        : line.includes("private")
        ? ("private" as const)
        : line.includes("internal")
        ? ("internal" as const)
        : line.includes("external")
        ? ("external" as const)
        : undefined;

      const modifiers =
        line
          .match(/modifier\s+(\w+)/g)
          ?.map((m) => m.replace("modifier ", "")) || [];

      currentFunction = {
        code: line,
        hasExternalCall: false,
        hasStateChange: false,
        isPayable: line.includes("payable"),
        visibility,
        hasModifier: modifiers.length > 0,
        modifiers,
      };
      functionStartLine = i;
    } else if (currentFunction) {
      currentFunction.code += "\n" + line;

      // Check for external calls with proper pattern matching
      if (line.match(/\.(call|send|transfer)\s*[({]/)) {
        currentFunction.hasExternalCall = true;
      }

      // Check for state changes with proper pattern matching
      if (line.match(/([+=]|[-=]|= [^=])/)) {
        currentFunction.hasStateChange = true;
      }
    }
  }

  // Analyze last function
  if (currentFunction) {
    analyzeFunction(currentFunction, functionStartLine, results);
  }

  // Apply SmartCheck rules with improved pattern matching
  lines.forEach((line, index) => {
    rules.forEach((rule) => {
      const result = rule.check(line, index + 1);
      if (result) {
        // Only add if we don't already have a similar result
        if (
          !results.some(
            (r) => r.rule === result.rule && Math.abs(r.line - result.line) <= 2
          )
        ) {
          results.push(result);
        }
      }
    });
  });

  return results;
}

function analyzeFunction(
  func: {
    code: string;
    hasExternalCall: boolean;
    hasStateChange: boolean;
    isPayable: boolean;
    visibility: "public" | "private" | "internal" | "external" | undefined;
    hasModifier: boolean;
    modifiers: string[];
  },
  startLine: number,
  results: SmartCheckResult[]
) {
  const lines = func.code.split("\n");
  const functionName = func.code.match(/function\s+(\w+)/)?.[1] || "";

  // Check visibility
  if (
    func.visibility === "public" &&
    !func.code.includes("pure") &&
    !func.code.includes("view")
  ) {
    results.push({
      severity: "medium",
      message: "Public function without state mutability specifier",
      line: startLine + 1,
      column: 1,
      rule: "visibility",
      description:
        "Public functions should explicitly declare their state mutability.",
      recommendation:
        "Add stateMutability specifier (pure, view, payable, or nonpayable) to the function.",
    });
  }

  // Check payable functions
  if (func.isPayable) {
    const hasValueValidation = lines.some(
      (line) =>
        line.trim().startsWith("require(msg.value") ||
        line.trim().startsWith("if (msg.value")
    );

    if (!hasValueValidation) {
      results.push({
        severity: "medium",
        message: "Payable function without value validation",
        line: startLine + 1,
        column: 1,
        rule: "payable-validation",
        description: "Payable functions should validate the received value.",
        recommendation:
          "Add require(msg.value > 0) or similar validation at the start of the function.",
      });
    }
  }

  // Check for reentrancy
  if (func.hasExternalCall && func.hasStateChange) {
    const stateChangeIndex = lines.findIndex((line) =>
      line.match(/([+=]|[-=]|= [^=])/)
    );
    const externalCallIndex = lines.findIndex((line) =>
      line.match(/\.(call|send|transfer)\s*[({]/)
    );

    if (stateChangeIndex > externalCallIndex) {
      results.push({
        severity: "high",
        message: "Potential reentrancy vulnerability detected",
        line: startLine + 1,
        column: 1,
        rule: "reentrancy",
        description:
          "State changes are made after external calls, which could lead to reentrancy attacks.",
        recommendation:
          "Use the Checks-Effects-Interactions pattern or a reentrancy guard.",
      });
    }
  }

  // Check for unprotected functions
  const isProtected = func.hasModifier && func.modifiers.includes("onlyOwner");

  if (!isProtected) {
    // Check for initialize function
    if (functionName === "initialize") {
      results.push({
        severity: "high",
        message: "Unprotected initialization function",
        line: startLine + 1,
        column: 1,
        rule: "unprotected-init",
        description:
          "Initialization function should be protected from multiple calls.",
        recommendation: "Add an initialization guard using a boolean flag.",
      });
    }

    // Check for upgrade function
    if (functionName === "upgrade") {
      results.push({
        severity: "high",
        message: "Unprotected upgrade function",
        line: startLine + 1,
        column: 1,
        rule: "unprotected-upgrade",
        description:
          "Upgrade functions should be protected with access control.",
        recommendation: "Add onlyOwner modifier or similar access control.",
      });
    }

    // Check for withdraw function
    if (functionName === "withdraw") {
      results.push({
        severity: "high",
        message: "Unprotected withdraw function",
        line: startLine + 1,
        column: 1,
        rule: "unprotected-withdraw",
        description:
          "Withdraw functions should be protected with access control.",
        recommendation: "Add onlyOwner modifier or similar access control.",
      });
    }

    // Check for selfdestruct function
    if (lines.some((line) => line.includes("selfdestruct"))) {
      results.push({
        severity: "high",
        message: "Unprotected selfdestruct function",
        line: startLine + 1,
        column: 1,
        rule: "unprotected-selfdestruct",
        description:
          "Selfdestruct functions should be protected with access control.",
        recommendation: "Add onlyOwner modifier or similar access control.",
      });
    }
  }
}

export async function analyzeContract(
  sourceCode: string
): Promise<SmartCheckResult[]> {
  try {
    if (!sourceCode || typeof sourceCode !== "string") {
      return [
        {
          severity: "error",
          message: "Invalid source code provided",
          line: 1,
          column: 1,
          rule: "input-validation",
          description: "The provided source code is empty or invalid.",
          recommendation: "Please provide valid Solidity source code.",
        },
      ];
    }

    const processedCode = preprocessSolidityCode(sourceCode);
    let results = analyzeContractSimple(processedCode);

    // Only add "No issues found" if there are no actual issues
    if (results.length === 0 || results.every((r) => r.severity === "info")) {
      results = [
        {
          severity: "info",
          message: "No issues found",
          line: 1,
          column: 1,
          rule: "analysis-complete",
          description:
            "The contract analysis completed successfully with no issues detected.",
          recommendation:
            "Continue monitoring for potential vulnerabilities as the contract evolves.",
        },
      ];
    }

    // Store analysis results if user is authenticated
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (user) {
      await supabase.from("analysis_results").insert({
        source_code: sourceCode,
        results,
        user_id: user.id,
      });
    }

    return results;
  } catch (error) {
    console.error("Error analyzing contract:", error);
    return [
      {
        severity: "error",
        message: "Analysis error",
        line: 1,
        column: 1,
        rule: "internal-error",
        description: "An error occurred while analyzing the contract.",
        recommendation:
          "Please try again or contact support if the issue persists.",
      },
    ];
  }
}

export async function getAnalysisHistory(): Promise<
  {
    source_code: string;
    results: SmartCheckResult[];
    created_at: string;
  }[]
> {
  const { data, error } = await supabase
    .from("analysis_results")
    .select("source_code, results, created_at")
    .order("created_at", { ascending: false });

  if (error) throw error;
  return data || [];
}
