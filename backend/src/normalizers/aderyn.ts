/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Aderyn output normalizer.
 *
 * Aderyn is Cyfrin's Rust-based static analyzer. It outputs a markdown
 * report by default, but with `--output report.json` produces structured
 * JSON. We normalize it here.
 *
 * Aderyn excels at gas optimizations and best-practice checks, complementing
 * Slither's security focus and Mythril's depth.
 *
 * Reference: https://github.com/Cyfrin/aderyn
 */

import { NormalizedFinding, Severity, Confidence, SourceLocation } from '../types/finding';

interface AderynInstance {
  contract_path: string;
  line_no: number;
  src: string;
  src_char: string;
}

interface AderynIssue {
  title: string;
  description: string;
  detector_name: string;
  instances: AderynInstance[];
}

interface AderynOutput {
  files_summary?: {
    total_source_units?: number;
    total_sloc?: number;
  };
  files_details?: unknown;
  issue_count?: {
    high?: number;
    low?: number;
  };
  high_issues?: { issues: AderynIssue[] };
  low_issues?: { issues: AderynIssue[] };
  nc_issues?: { issues: AderynIssue[] };  // non-critical
}

/**
 * Aderyn detector names that we elevate to critical based on impact.
 */
const CRITICAL_DETECTORS = new Set([
  'delegate-call-on-uninitialized-storage-pointer',
  'arbitrary-transfer-from',
  'unprotected-init-function',
  'reentrancy-state-change-after-external-call',
]);

const SLITHER_COMPAT_MAP: Record<string, string> = {
  // Map Aderyn detector names to Slither check names for consensus clustering
  'reentrancy-state-change-after-external-call': 'reentrancy-eth',
  'unprotected-init-function': 'unprotected-upgrade',
  'use-of-tx-origin': 'tx-origin',
  'block-timestamp-deadline': 'timestamp',
  'delegate-call-on-uninitialized-storage-pointer': 'controlled-delegatecall',
  'unchecked-low-level-call': 'unchecked-lowlevel',
  'send-ether-no-checks': 'arbitrary-send-eth',
  'unchecked-send': 'unchecked-send',
  'arbitrary-transfer-from': 'arbitrary-send-erc20',
};

const ADERYN_TO_SWC: Record<string, string> = {
  'reentrancy-state-change-after-external-call': 'SWC-107',
  'use-of-tx-origin': 'SWC-115',
  'block-timestamp-deadline': 'SWC-116',
  'unchecked-low-level-call': 'SWC-104',
  'delegate-call-on-uninitialized-storage-pointer': 'SWC-112',
  'arbitrary-transfer-from': 'SWC-105',
  'unprotected-init-function': 'SWC-118',
  'centralization-risk': 'SWC-105',
};

function mapSeverity(bucket: 'high' | 'low' | 'nc', detector: string): Severity {
  if (CRITICAL_DETECTORS.has(detector)) return 'critical';
  switch (bucket) {
    case 'high': return 'high';
    case 'low': return 'low';
    case 'nc': return 'info';
  }
}

function processBucket(
  bucket: 'high' | 'low' | 'nc',
  issues: AderynIssue[] | undefined,
  startIdx: number
): NormalizedFinding[] {
  if (!issues) return [];
  const findings: NormalizedFinding[] = [];
  let i = startIdx;

  for (const issue of issues) {
    for (const inst of issue.instances) {
      const location: SourceLocation = {
        file: inst.contract_path,
        startLine: inst.line_no,
      };

      findings.push({
        id: `aderyn_${i++}`,
        tool: 'aderyn',
        detectorId: SLITHER_COMPAT_MAP[issue.detector_name] || issue.detector_name,
        category: categorize(issue.detector_name),
        severity: mapSeverity(bucket, issue.detector_name),
        confidence: 'high', // Aderyn is AST-based, low false-positive rate
        title: issue.title,
        description: issue.description,
        swcId: ADERYN_TO_SWC[issue.detector_name],
        location,
        raw: { ...issue, instance: inst },
      });
    }
  }

  return findings;
}

export function normalizeAderynOutput(output: AderynOutput): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  findings.push(...processBucket('high', output.high_issues?.issues, 0));
  findings.push(...processBucket('low', output.low_issues?.issues, findings.length));
  findings.push(...processBucket('nc', output.nc_issues?.issues, findings.length));
  return findings;
}

function categorize(name: string): string {
  if (name.includes('reentrancy')) return 'reentrancy';
  if (name.includes('delegate')) return 'delegatecall';
  if (name.includes('tx-origin')) return 'access-control';
  if (name.includes('timestamp') || name.includes('block')) return 'time-dependence';
  if (name.includes('unchecked')) return 'unchecked-call';
  if (name.includes('arithmetic') || name.includes('overflow')) return 'arithmetic';
  if (name.includes('gas') || name.includes('optimization')) return 'gas';
  return 'other';
}
