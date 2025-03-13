import { supabase } from "../lib/supabase";

interface SmartCheckResult {
  severity: "high" | "medium" | "low" | "info" | "error";
  message: string;
  line: number;
  column: number;
  rule: string;
  description: string;
  recommendation: string;
}

interface FunctionAnalysis {
  code: string;
  hasExternalCall: boolean;
  hasStateChange: boolean;
  isPayable: boolean;
  visibility: "public" | "private" | "internal" | "external" | undefined;
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

  // Find and analyze functions
  let currentFunction: FunctionAnalysis | null = null;
  let functionStartLine = 0;

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

      currentFunction = {
        code: line,
        hasExternalCall: false,
        hasStateChange: false,
        isPayable: line.includes("payable"),
        visibility,
      };
      functionStartLine = i;
    } else if (currentFunction) {
      currentFunction.code += "\n" + line;

      // Check for external calls
      if (
        line.includes(".call{") ||
        line.includes(".send(") ||
        line.includes(".transfer(")
      ) {
        currentFunction.hasExternalCall = true;
      }

      // Check for state changes
      if (
        line.includes("balances[") ||
        line.includes("+=") ||
        line.includes("-=")
      ) {
        currentFunction.hasStateChange = true;
      }
    }
  }

  // Analyze last function
  if (currentFunction) {
    analyzeFunction(currentFunction, functionStartLine, results);
  }

  return results;
}

function analyzeFunction(
  func: FunctionAnalysis,
  startLine: number,
  results: SmartCheckResult[]
) {
  // Check reentrancy
  if (func.hasExternalCall && func.hasStateChange) {
    results.push({
      severity: "high",
      message: "Potential reentrancy vulnerability detected",
      line: startLine + 1,
      column: 1,
      rule: "reentrancy",
      description:
        "The contract may be vulnerable to reentrancy attacks. State changes are made after external calls.",
      recommendation:
        "Consider using the Checks-Effects-Interactions pattern or a reentrancy guard.",
    });
  }

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
  if (func.isPayable && !func.code.includes("require(msg.value")) {
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

    if (results.length === 0) {
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
        description: "An internal error occurred while analyzing the contract.",
        recommendation:
          "Please try again with valid Solidity code. If the error persists, check the contract syntax.",
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
