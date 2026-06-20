// SPDX-License-Identifier: MIT
// FORENSIQ TEST FIXTURE — Arbitrary delegatecall + unchecked send
// Expected findings: arbitrary delegatecall (SWC-112) — critical;
// unchecked low-level call return value. Flagged by slither + mythril.
pragma solidity ^0.8.0;

contract DelegateProxy {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: arbitrary delegatecall destination
    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        target.delegatecall(data);   // attacker-controlled target
    }

    // VULNERABLE: unchecked return value on low-level call
    function payout(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        to.call{value: amount}("");  // return value ignored
    }

    receive() external payable {}
}
