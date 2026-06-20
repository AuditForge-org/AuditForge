// SPDX-License-Identifier: MIT
// FORENSIQ TEST FIXTURE — tx.origin authorization
// Expected findings: tx.origin used for auth (SWC-115), flagged by
// slither + solhint + semgrep. High severity.
pragma solidity ^0.8.0;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin can be phished
    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        to.transfer(amount);
    }

    receive() external payable {}
}
