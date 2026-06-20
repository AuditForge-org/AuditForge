/**
 * Tests for fuzz, webhook, and registry modules.
 *
 * These cover the trust-critical paths beyond consensus:
 *   - Echidna harness generation produces valid Solidity for common patterns
 *   - GitHub webhook HMAC verification is timing-safe and correct
 *   - Echidna findings get high confidence even single-tool
 */

import { describe, expect, it } from 'vitest';
import { createHmac } from 'crypto';
import { parseContract, generateHarness } from '../src/fuzz/harness';
import { verifyGithubSignature } from '../src/webhooks/github';
import { buildConsensus, calculateScore } from '../src/consensus/engine';
import { NormalizedFinding } from '../src/types/finding';

// ─── Harness generation ──────────────────────────────────────────────

describe('Echidna harness generation', () => {
  const sampleERC20 = `
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract MyToken {
      mapping(address => uint256) public balanceOf;
      uint256 public totalSupply;
      address public owner;
      uint256 public totalMinted;

      constructor() {
        owner = msg.sender;
      }

      function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
      }

      function mint(address to, uint256 amount) external {
        require(msg.sender == owner);
        balanceOf[to] += amount;
        totalSupply += amount;
        totalMinted += amount;
      }
    }
  `;

  it('detects ERC20-like patterns', () => {
    const parsed = parseContract(sampleERC20);
    expect(parsed.name).toBe('MyToken');
    expect(parsed.isERC20).toBe(true);
    expect(parsed.hasMint).toBe(true);
    expect(parsed.isOwnable).toBe(true);
    expect(parsed.publicFunctions.map(f => f.name)).toContain('transfer');
    expect(parsed.publicFunctions.map(f => f.name)).toContain('mint');
  });

  it('generates harness with ERC20 invariants', () => {
    const parsed = parseContract(sampleERC20);
    const { harness, config } = generateHarness(parsed, sampleERC20);

    // Should declare the harness contract
    expect(harness).toMatch(/contract\s+EchidnaMyToken/);
    // Should include the universal invariant
    expect(harness).toMatch(/echidna_contract_exists/);
    // Should include ERC20 sum invariant
    expect(harness).toMatch(/echidna_total_supply_equals_balance_sum/);
    // Should include owner invariant (ownable detected)
    expect(harness).toMatch(/echidna_owner_not_zero/);
    // Should include fuzz entry for transfer
    expect(harness).toMatch(/fuzz_transfer/);
    // Config should specify property mode
    expect(config).toMatch(/testMode:\s*"property"/);
  });

  it('detects monotonic counters', () => {
    const parsed = parseContract(sampleERC20);
    const { harness } = generateHarness(parsed, sampleERC20);
    // totalMinted matches counter heuristic (contains "total")
    expect(harness).toMatch(/echidna_totalMinted_monotonic|echidna_totalSupply_monotonic/);
  });
});

// ─── Webhook HMAC ────────────────────────────────────────────────────

describe('GitHub webhook signature verification', () => {
  const secret = 'test-secret-deadbeef';
  const body = Buffer.from('{"ref":"refs/heads/main","repository":{"full_name":"a/b"}}');
  const signature = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');

  it('accepts a valid signature', () => {
    expect(verifyGithubSignature(body, signature, secret)).toBe(true);
  });

  it('rejects an invalid signature', () => {
    expect(verifyGithubSignature(body, 'sha256=deadbeef', secret)).toBe(false);
  });

  it('rejects missing signature', () => {
    expect(verifyGithubSignature(body, undefined, secret)).toBe(false);
  });

  it('rejects signature with wrong prefix', () => {
    const sigNoPrefix = signature.replace('sha256=', 'md5=');
    expect(verifyGithubSignature(body, sigNoPrefix, secret)).toBe(false);
  });

  it('rejects when body is tampered', () => {
    const tampered = Buffer.from(body.toString().replace('main', 'evil'));
    expect(verifyGithubSignature(tampered, signature, secret)).toBe(false);
  });

  it('rejects when secret is wrong', () => {
    expect(verifyGithubSignature(body, signature, 'different-secret')).toBe(false);
  });
});

// ─── Echidna confidence in consensus ────────────────────────────────

function f(partial: Partial<NormalizedFinding> & {
  tool: NormalizedFinding['tool'];
  severity: NormalizedFinding['severity'];
  line: number;
}): NormalizedFinding {
  return {
    id: `${partial.tool}_${partial.line}`,
    tool: partial.tool,
    detectorId: partial.detectorId || 'generic',
    category: partial.category || 'invariant',
    severity: partial.severity,
    confidence: partial.confidence || 'high',
    title: partial.title || 'Generic',
    description: partial.description || 'Test',
    location: { file: 'Contract.sol', startLine: partial.line },
  };
}

describe('Echidna in consensus', () => {
  it('single-tool echidna finding gets high consensus confidence', () => {
    const findings = [
      f({ tool: 'echidna', severity: 'critical', line: 0, detectorId: 'property_violation:echidna_owner_not_zero' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus[0].consensusConfidence).toBe('high');
    expect(consensus[0].tools).toContain('echidna');
  });

  it('echidna single-tool finding penalizes score like a 2-tool consensus', () => {
    const echidnaOnly = buildConsensus([
      f({ tool: 'echidna', severity: 'critical', line: 0 }),
    ]);
    const slitherOnly = buildConsensus([
      f({ tool: 'slither', severity: 'critical', line: 0 }),
    ]);
    // Echidna single (multiplier 1.0) > Slither single (multiplier 0.5)
    expect(calculateScore(echidnaOnly).score).toBeLessThan(calculateScore(slitherOnly).score);
  });
});
