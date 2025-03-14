import { useState } from "react";
import { AlertCircle, Code2, FileWarning } from "lucide-react";
import Editor from "@monaco-editor/react";
import {
  analyzeContract,
  SmartCheckResult,
} from "../services/smartcheck-service";

const SAMPLE_CONTRACT = `pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}`;

export function CodeAnalyzer() {
  const [code, setCode] = useState(SAMPLE_CONTRACT);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState<SmartCheckResult[]>([]);
  const [error, setError] = useState<string>("");
  const [selectedResult, setSelectedResult] = useState<SmartCheckResult | null>(
    null
  );

  const analyzeCode = async () => {
    setAnalyzing(true);
    setError("");
    setResults([]);
    setSelectedResult(null);

    try {
      const analysisResults = await analyzeContract(code);
      setResults(analysisResults);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to analyze code. Please try again."
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "text-red-600 bg-red-50";
      case "medium":
        return "text-orange-600 bg-orange-50";
      case "low":
        return "text-yellow-600 bg-yellow-50";
      default:
        return "text-blue-600 bg-blue-50";
    }
  };

  return (
    <div className="space-y-6">
      <div className="border rounded-lg overflow-hidden">
        <div className="bg-gray-50 px-4 py-2 border-b flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code2 className="h-5 w-5 text-gray-500" />
            <span className="font-medium">Smart Contract Code</span>
          </div>
          <button
            onClick={analyzeCode}
            disabled={analyzing}
            className="px-4 py-1.5 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            {analyzing ? "Analyzing..." : "Analyze Code"}
          </button>
        </div>
        <Editor
          height="400px"
          defaultLanguage="sol"
          value={code}
          onChange={(value) => setCode(value || "")}
          theme="vs-dark"
          options={{
            minimap: { enabled: false },
            fontSize: 14,
            lineNumbers: "on",
            readOnly: analyzing,
          }}
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-red-600 bg-red-50 p-4 rounded-lg">
          <AlertCircle className="h-5 w-5" />
          <span>{error}</span>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <FileWarning className="h-6 w-6" />
            Analysis Results
          </h2>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-3">
              {results.map((result, index) => (
                <button
                  key={index}
                  onClick={() => setSelectedResult(result)}
                  className={`w-full p-4 rounded-lg ${getSeverityColor(
                    result.severity
                  )} text-left transition-colors hover:opacity-90`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-semibold">{result.rule}</h3>
                      <p className="mt-1">{result.message}</p>
                    </div>
                    <span className="text-sm whitespace-nowrap ml-4">
                      Line {result.line}
                    </span>
                  </div>
                </button>
              ))}
            </div>

            {selectedResult && (
              <div className="bg-gray-50 p-6 rounded-lg">
                <h3 className="text-lg font-semibold mb-4">
                  {selectedResult.rule}
                </h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium text-gray-700">Description</h4>
                    <p className="mt-1 text-gray-600">
                      {selectedResult.description}
                    </p>
                  </div>
                  {selectedResult.recommendation && (
                    <div>
                      <h4 className="font-medium text-gray-700">
                        Recommendation
                      </h4>
                      <p className="mt-1 text-gray-600">
                        {selectedResult.recommendation}
                      </p>
                    </div>
                  )}
                  <div>
                    <h4 className="font-medium text-gray-700">Location</h4>
                    <p className="mt-1 text-gray-600">
                      Line {selectedResult.line}, Column {selectedResult.column}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
