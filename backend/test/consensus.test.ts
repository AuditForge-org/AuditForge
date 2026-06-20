/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Consensus engine tests.
 *
 * The clustering and scoring logic is what users will trust. These tests
 * verify the high-stakes scenarios:
 *   - Multi-tool agreement on the same bug clusters into one finding
 *   - Same bug class on different lines stays separate
 *   - Severity disagreements are surfaced
 *   - Single-tool findings get downgraded confidence
 *   - Score weighting reflects tool agreement
 */

import { describe, expect, it } from 'vitest';
import { buildConsensus, calculateScore } from '../src/consensus/engine';
import { NormalizedFinding } from '../src/types/finding';

function f(partial: Partial<NormalizedFinding> & {
  tool: NormalizedFinding['tool'];
  severity: NormalizedFinding['severity'];
  line: number;
  file?: string;
}): NormalizedFinding {
  return {
    id: `${partial.tool}_${partial.line}`,
    tool: partial.tool,
    detectorId: partial.detectorId || 'generic',
    category: partial.category || 'other',
    severity: partial.severity,
    confidence: partial.confidence || 'high',
    title: partial.title || 'Generic finding',
    description: partial.description || 'Test finding',
    swcId: partial.swcId,
    location: { file: partial.file || 'Contract.sol', startLine: partial.line },
  };
}

describe('consensus clustering', () => {
  it('clusters reentrancy detected by Slither + Mythril + Aderyn into one finding', () => {
    const findings = [
      f({ tool: 'slither', severity: 'critical', line: 42, detectorId: 'reentrancy-eth', swcId: 'SWC-107', title: 'Reentrancy' }),
      f({ tool: 'mythril', severity: 'high', line: 43, detectorId: 'SWC-107', swcId: 'SWC-107', title: 'External call followed by state write' }),
      f({ tool: 'aderyn', severity: 'high', line: 42, detectorId: 'reentrancy-state-change-after-external-call', swcId: 'SWC-107', title: 'Reentrancy' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus).toHaveLength(1);
    expect(consensus[0].toolCount).toBe(3);
    expect(consensus[0].tools.sort()).toEqual(['aderyn', 'mythril', 'slither']);
    expect(consensus[0].severity).toBe('critical');  // max wins
    expect(consensus[0].consensusConfidence).toBe('high');
  });

  it('clusters the same bug across tools that report different path representations', () => {
    // Regression: engines name the same file differently (slither: contracts/Vault.sol,
    // mythril: /input/Vault.sol, aderyn: Vault.sol). Clustering must match on basename,
    // not full path, or consensus silently breaks.
    const findings = [
      f({ tool: 'slither', severity: 'high', line: 42, swcId: 'SWC-107', detectorId: 'reentrancy-eth', file: 'contracts/Vault.sol' }),
      f({ tool: 'mythril', severity: 'high', line: 42, swcId: 'SWC-107', file: '/input/Vault.sol' }),
      f({ tool: 'aderyn', severity: 'high', line: 43, swcId: 'SWC-107', detectorId: 'reentrancy-state-change', file: 'Vault.sol' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus).toHaveLength(1);
    expect(consensus[0].toolCount).toBe(3);
  });

  it('keeps separate clusters when same category appears at distant lines', () => {
    const findings = [
      f({ tool: 'slither', severity: 'critical', line: 10, detectorId: 'reentrancy-eth', swcId: 'SWC-107' }),
      f({ tool: 'slither', severity: 'critical', line: 200, detectorId: 'reentrancy-eth', swcId: 'SWC-107' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus).toHaveLength(2);
  });

  it('surfaces severity disagreement when tools disagree', () => {
    const findings = [
      f({ tool: 'slither', severity: 'high', line: 50, swcId: 'SWC-116', detectorId: 'timestamp' }),
      f({ tool: 'mythril', severity: 'medium', line: 50, swcId: 'SWC-116' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus).toHaveLength(1);
    expect(consensus[0].severity).toBe('high');
    expect(consensus[0].severityDisagreement).toBeDefined();
    expect(consensus[0].severityDisagreement?.reported.slither).toBe('high');
    expect(consensus[0].severityDisagreement?.reported.mythril).toBe('medium');
  });

  it('downgrades confidence on single-tool findings', () => {
    const findings = [
      f({ tool: 'solhint', severity: 'low', line: 5, confidence: 'low' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus[0].consensusConfidence).toBe('low');
  });

  it('keeps high confidence when 2 high-confidence tools agree', () => {
    const findings = [
      f({ tool: 'slither', severity: 'high', line: 10, swcId: 'SWC-115', detectorId: 'tx-origin', confidence: 'high' }),
      f({ tool: 'aderyn', severity: 'high', line: 10, swcId: 'SWC-115', detectorId: 'use-of-tx-origin', confidence: 'high' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus[0].consensusConfidence).toBe('high');
    expect(consensus[0].toolCount).toBe(2);
  });
});

describe('scoring', () => {
  it('clean contract scores 100', () => {
    expect(calculateScore([]).score).toBe(100);
    expect(calculateScore([]).grade).toMatch(/^A/);
  });

  it('multi-tool critical is penalized more than single-tool critical', () => {
    const single = buildConsensus([
      f({ tool: 'slither', severity: 'critical', line: 1, swcId: 'SWC-107', detectorId: 'reentrancy-eth' }),
    ]);
    const multi = buildConsensus([
      f({ tool: 'slither', severity: 'critical', line: 1, swcId: 'SWC-107', detectorId: 'reentrancy-eth' }),
      f({ tool: 'mythril', severity: 'critical', line: 1, swcId: 'SWC-107' }),
      f({ tool: 'aderyn', severity: 'critical', line: 1, swcId: 'SWC-107', detectorId: 'reentrancy-state-change-after-external-call' }),
    ]);
    const singleScore = calculateScore(single).score;
    const multiScore = calculateScore(multi).score;
    expect(multiScore).toBeLessThan(singleScore);
  });

  it('grade thresholds work', () => {
    expect(calculateScore([]).grade).toMatch(/^A/);
    // A single high-severity finding with 1 tool: 12 * 0.5 = 6 penalty → 94 → A
    const oneHigh = buildConsensus([
      f({ tool: 'slither', severity: 'high', line: 1 }),
    ]);
    expect(calculateScore(oneHigh).score).toBe(94);
  });
});

describe('SWC cross-referencing', () => {
  it('clusters across tools using SWC ids even with different detector names', () => {
    const findings = [
      f({ tool: 'slither', severity: 'high', line: 30, detectorId: 'tx-origin', swcId: 'SWC-115' }),
      f({ tool: 'solhint', severity: 'high', line: 31, detectorId: 'avoid-tx-origin', swcId: 'SWC-115' }),
      f({ tool: 'aderyn', severity: 'high', line: 30, detectorId: 'use-of-tx-origin', swcId: 'SWC-115' }),
    ];
    const consensus = buildConsensus(findings);
    expect(consensus).toHaveLength(1);
    expect(consensus[0].toolCount).toBe(3);
    expect(consensus[0].swcId).toBe('SWC-115');
  });
});
