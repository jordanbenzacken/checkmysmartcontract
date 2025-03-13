import { parse } from 'solidity-parser-antlr';

function analyzeASTNode(node, results) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'FunctionDefinition') {
    // Check for reentrancy vulnerability
    const hasExternalCall = node.body?.statements?.some(stmt => 
      stmt.type === 'ExpressionStatement' && 
      stmt.expression?.type === 'FunctionCall' &&
      stmt.expression.expression?.type === 'MemberAccess' &&
      stmt.expression.expression.memberName === 'call'
    );

    const hasStateChange = node.body?.statements?.some(stmt =>
      stmt.type === 'ExpressionStatement' &&
      stmt.expression?.type === 'BinaryOperation' &&
      stmt.expression.operator === '-='
    );

    if (hasExternalCall && hasStateChange) {
      results.push({
        severity: 'high',
        message: 'Potential reentrancy vulnerability detected',
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        rule: 'reentrancy',
        description: 'The contract may be vulnerable to reentrancy attacks. State changes are made after external calls.',
        recommendation: 'Consider using the Checks-Effects-Interactions pattern or a reentrancy guard.'
      });
    }
  }

  // Recursively analyze child nodes
  for (const key in node) {
    if (node[key] && typeof node[key] === 'object') {
      if (Array.isArray(node[key])) {
        node[key].forEach(child => {
          if (child && typeof child === 'object') {
            analyzeASTNode(child, results);
          }
        });
      } else {
        analyzeASTNode(node[key], results);
      }
    }
  }
}

function preprocessSolidityCode(code) {
  // Normalize line endings
  let processedCode = code.replace(/\r\n/g, '\n').trim();
  
  // Add missing semicolons after require statements
  processedCode = processedCode.replace(
    /require\s*\([^;)]+\)(?!\s*;)/g,
    '$&;'
  );
  
  return processedCode;
}

export async function analyzeContract(sourceCode) {
  try {
    if (!sourceCode || typeof sourceCode !== 'string') {
      return [{
        severity: 'error',
        message: 'Invalid source code provided',
        line: 1,
        column: 1,
        rule: 'input-validation',
        description: 'The provided source code is empty or invalid.',
        recommendation: 'Please provide valid Solidity source code.'
      }];
    }

    const processedCode = preprocessSolidityCode(sourceCode);
    
    let ast;
    try {
      ast = parse(processedCode, { 
        loc: true,
        tolerant: false,
        range: true
      });
    } catch (parseError) {
      // Extract line and column from error message if available
      const errorMatch = parseError.message.match(/\((\d+):(\d+)\)/);
      const line = errorMatch ? parseInt(errorMatch[1]) : 1;
      const column = errorMatch ? parseInt(errorMatch[2]) : 1;
      
      // Count actual line number in the source code
      const lines = sourceCode.split('\n');
      const actualLine = lines.findIndex((line, index) => {
        return line.includes('require') && !line.includes(';') && index + 1 >= line;
      }) + 1;
      
      return [{
        severity: 'error',
        message: 'Syntax error in contract code',
        line: actualLine || line,
        column: column,
        rule: 'syntax',
        description: `Parser error: ${parseError.message}`,
        recommendation: 'Please check your contract syntax. Common issues include:\n' +
          '- Missing semicolons after statements\n' +
          '- Incorrect function declarations\n' +
          '- Mismatched braces\n' +
          '- Invalid pragma statements'
      }];
    }
    
    const results = [];
    analyzeASTNode(ast, results);
    
    return results.length > 0 ? results : [{
      severity: 'info',
      message: 'No issues found',
      line: 1,
      column: 1,
      rule: 'analysis-complete',
      description: 'The contract analysis completed successfully with no issues detected.',
      recommendation: 'Continue monitoring for potential vulnerabilities as the contract evolves.'
    }];
  } catch (error) {
    console.error('Error analyzing contract:', error);
    return [{
      severity: 'error',
      message: 'Analysis error',
      line: 1,
      column: 1,
      rule: 'internal-error',
      description: 'An internal error occurred while analyzing the contract.',
      recommendation: 'Please try again with valid Solidity code. If the error persists, check the contract syntax.'
    }];
  }
}