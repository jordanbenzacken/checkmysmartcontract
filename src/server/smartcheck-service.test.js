import { expect, test } from 'vitest';
import { analyzeContract } from './smartcheck-service.js';

test('should handle contract with missing semicolon at line 12', async () => {
  const contractWithError = `
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}`;

  const results = await analyzeContract(contractWithError);
  expect(results[0].severity).toBe('error');
  expect(results[0].line).toBe(12);
  expect(results[0].message).toContain('Syntax error');
});

test('should handle contract with correct semicolons', async () => {
  const validContract = `
pragma solidity ^0.8.0;

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

  const results = await analyzeContract(validContract);
  expect(results[0].severity).toBe('high');
  expect(results[0].rule).toBe('reentrancy');
});