// SPDX-License-Identifier: MIT
// FORENSIQ TEST FIXTURE — Clean contract (negative control)
// Expected findings: none critical/high. This SHOULD score well (A/B).
// If the platform flags critical issues here, the engines or normalizers
// are producing false positives — investigate.
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title A minimal, well-guarded vault
/// @notice Demonstrates checks-effects-interactions + reentrancy guard
contract SafeVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) private _balances;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() Ownable(msg.sender) {}

    function deposit() external payable {
        _balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw following checks-effects-interactions
    function withdraw(uint256 amount) external nonReentrant {
        require(_balances[msg.sender] >= amount, "insufficient");
        _balances[msg.sender] -= amount;            // effects first
        emit Withdrawn(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");  // interaction last
        require(ok, "transfer failed");
    }

    function balanceOf(address who) external view returns (uint256) {
        return _balances[who];
    }
}
