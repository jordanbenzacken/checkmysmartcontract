import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

interface CalculatorProps {
  onUnauthorized: () => void;
}

export function Calculator({ onUnauthorized }: CalculatorProps) {
  const [number, setNumber] = useState<string>('');
  const [result, setResult] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [steps, setSteps] = useState<number[]>([]);

  const calculateFactorial = (n: number): number => {
    if (n < 0) throw new Error('Negative numbers are not supported');
    if (n > 170) throw new Error('Number too large to calculate');
    if (n === 0 || n === 1) return 1;
    return n * calculateFactorial(n - 1);
  };

  const handleCalculate = () => {
    try {
      const num = parseInt(number);
      if (isNaN(num)) {
        setError('Please enter a valid number');
        setResult('');
        setSteps([]);
        return;
      }

      const calculatedSteps: number[] = [];
      for (let i = 1; i <= num; i++) {
        calculatedSteps.push(i);
      }
      
      const factorial = calculateFactorial(num);
      setResult(factorial.toLocaleString());
      setSteps(calculatedSteps);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setResult('');
      setSteps([]);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex gap-4">
        <input
          type="number"
          value={number}
          onChange={(e) => setNumber(e.target.value)}
          placeholder="Enter a number"
          className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={handleCalculate}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          Calculate
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-red-600 bg-red-50 p-4 rounded-lg">
          <AlertCircle className="h-5 w-5" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-green-600 bg-green-50 p-4 rounded-lg">
            <CheckCircle2 className="h-5 w-5" />
            <span>Result: {result}</span>
          </div>
          
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-3">Calculation Steps</h3>
            <div className="flex flex-wrap gap-2">
              {steps.map((step, index) => (
                <div
                  key={step}
                  className="px-3 py-1 bg-white border border-gray-200 rounded-full text-sm"
                >
                  {index === steps.length - 1 ? step : `${step} ×`}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}