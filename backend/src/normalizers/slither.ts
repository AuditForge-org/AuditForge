/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Slither output normalizer.
 *
 * Slither runs with `--json -` and emits a top-level object with
 * `results.detectors[]`. Each detector entry has its own check name,
 * impact, confidence, and an `elements[]` array describing source
 * locations.
 *
 * Reference: https://github.com/crytic/slither/wiki/JSON-output
 */

import { NormalizedFinding, Severity, Confidence, SourceLocation } from '../types/finding';

interface SlitherElement {
  type: string;
  name: string;
  source_mapping?: {
    filename_relative?: string;
    filename_absolute?: string;
    lines?: number[];
    starting_column?: number;
    ending_column?: number;
  };
}

interface SlitherDetectorResult {
  check: string;
  impact: 'High' | 'Medium' | 'Low' | 'Informational' | 'Optimization';
  confidence: 'High' | 'Medium' | 'Low';
  description: string;
  markdown?: string;
  id?: string;
  elements: SlitherElement[];
}

interface SlitherOutput {
  success: boolean;
  error: string | null;
  results: {
    detectors?: SlitherDetectorResult[];
  };
}

/**
 * Slither's "Impact" field maps to our severity. We separately handle the
 * special case where impact=High but the detector covers theft (we promote
 * to critical) — this is based on the detector's check name.
 */
const CRITICAL_DETECTORS = new Set([
  'arbitrary-send-eth',
  'arbitrary-send-erc20',
  'arbitrary-send-erc20-permit',
  'controlled-delegatecall',
  'reentrancy-eth',
  'suicidal',
  'unprotected-upgrade',
]);

function mapSeverity(impact: SlitherDetectorResult['impact'], check: string): Severity {
  if (CRITICAL_DETECTORS.has(check)) return 'critical';
  switch (impact) {
    case 'High': return 'high';
    case 'Medium': return 'medium';
    case 'Low': return 'low';
    case 'Informational':
    case 'Optimization':
    default: return 'info';
  }
}

function mapConfidence(c: SlitherDetectorResult['confidence']): Confidence {
  return c.toLowerCase() as Confidence;
}

/**
 * Slither's check names map roughly to SWC ids. This table is the
 * authoritative mapping used by the consensus engine to cluster findings
 * across tools.
 */
const SLITHER_TO_SWC: Record<string, string> = {
  'reentrancy-eth': 'SWC-107',
  'reentrancy-no-eth': 'SWC-107',
  'reentrancy-benign': 'SWC-107',
  'reentrancy-events': 'SWC-107',
  'tx-origin': 'SWC-115',
  'timestamp': 'SWC-116',
  'block-other-parameters': 'SWC-120',
  'weak-prng': 'SWC-120',
  'arbitrary-send-eth': 'SWC-105',
  'controlled-delegatecall': 'SWC-112',
  'delegatecall-loop': 'SWC-112',
  'suicidal': 'SWC-106',
  'uninitialized-state': 'SWC-109',
  'uninitialized-storage': 'SWC-109',
  'unchecked-send': 'SWC-104',
  'unchecked-lowlevel': 'SWC-104',
  'unchecked-transfer': 'SWC-104',
  'shadowing-state': 'SWC-119',
  'shadowing-abstract': 'SWC-119',
  'incorrect-shift': 'SWC-128',
  'assembly': 'SWC-127',
  'low-level-calls': 'SWC-104',
  'solc-version': 'SWC-103',
  'pragma': 'SWC-103',
  'naming-convention': 'SWC-129',
  'unused-return': 'SWC-104',
};

/**
 * Pick the most useful source location from a Slither finding.
 * Slither often returns multiple elements; we prefer the first one
 * that has a clear line number.
 */
function extractLocation(elements: SlitherElement[]): SourceLocation {
  for (const el of elements) {
    const sm = el.source_mapping;
    if (sm?.lines && sm.lines.length > 0) {
      return {
        file: sm.filename_relative || sm.filename_absolute || 'unknown',
        startLine: sm.lines[0],
        endLine: sm.lines[sm.lines.length - 1],
        startCol: sm.starting_column,
        endCol: sm.ending_column,
      };
    }
  }
  return { file: 'unknown', startLine: 0 };
}

export function normalizeSlitherOutput(output: SlitherOutput): NormalizedFinding[] {
  if (!output?.success || !output.results?.detectors) return [];

  return output.results.detectors.map((d, i): NormalizedFinding => {
    const location = extractLocation(d.elements || []);
    return {
      id: `slither_${d.id || i}`,
      tool: 'slither',
      detectorId: d.check,
      // Use the full check name as the category. The previous
      // `check.split('-')[0]` truncated "tx-origin"→"tx" and
      // "controlled-delegatecall"→"controlled", losing all meaning.
      category: d.check || 'other',
      severity: mapSeverity(d.impact, d.check),
      confidence: mapConfidence(d.confidence),
      title: humanizeCheckName(d.check),
      description: d.description.trim(),
      swcId: SLITHER_TO_SWC[d.check],
      location,
      raw: d,
    };
  });
}

function humanizeCheckName(check: string): string {
  return check
    .split('-')
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}
