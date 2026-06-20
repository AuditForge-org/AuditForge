// SPDX-License-Identifier: MIT
// FORENSIQ TEST FIXTURE — Reentrancy
// Expected findings: reentrancy (SWC-107) in withdraw(), flagged by
// slither + aderyn + mythril. This is the canonical DAO-style bug.
pragma solidity ^0.8.0;

contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;   // state update AFTER call
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
