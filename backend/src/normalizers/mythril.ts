/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Mythril output normalizer.
 *
 * Mythril runs with `-o jsonv2` and emits a top-level array of "issue groups",
 * each with `issues[]`. Each issue has SWC id, severity, title, description,
 * and source location.
 *
 * Mythril is a symbolic execution engine — slower than Slither but catches
 * deeper logic bugs that AST-based tools miss (integer arithmetic paths,
 * state-dependent exploits).
 *
 * Reference: https://mythril-classic.readthedocs.io/en/master/security-analysis.html
 */

import { NormalizedFinding, Severity, Confidence, SourceLocation } from '../types/finding';

interface MythrilLocation {
  sourceMap?: string;
  sourceType?: 'solidity-file' | 'raw-bytecode';
  sourceFormat?: string;
}

interface MythrilExtra {
  discoveryTime?: number;
  testCases?: unknown[];
}

interface MythrilIssue {
  swcID: string;
  swcTitle: string;
  description: {
    head: string;
    tail: string;
  };
  severity: 'High' | 'Medium' | 'Low';
  locations: Array<{
    sourceMap: string;
    sourceType?: string;
    sourceFormat?: string;
    sourceList?: string[];
  }>;
  extra?: MythrilExtra;
}

interface MythrilGroup {
  issues: MythrilIssue[];
  sourceType: string;
  sourceFormat: string;
  sourceList: string[];
  meta: Record<string, unknown>;
}

/**
 * Mythril's SWC IDs we treat as critical regardless of its reported severity,
 * because they map to direct fund-loss scenarios.
 */
const CRITICAL_SWC = new Set([
  'SWC-105', // Unprotected ether withdrawal
  'SWC-106', // Unprotected SELFDESTRUCT
  'SWC-112', // Delegatecall to untrusted callee
]);

function mapSeverity(swc: string, sev: MythrilIssue['severity']): Severity {
  if (CRITICAL_SWC.has(swc)) return 'critical';
  switch (sev) {
    case 'High': return 'high';
    case 'Medium': return 'medium';
    case 'Low': return 'low';
    default: return 'info';
  }
}

/**
 * Parse Mythril's sourceMap format "start:length:fileIndex".
 * We need to convert byte offsets to line numbers using the original source.
 */
function parseSourceMap(sourceMap: string, sourceText?: string): { startLine: number; endLine?: number } {
  const parts = sourceMap.split(':');
  if (parts.length < 2) return { startLine: 0 };
  const start = parseInt(parts[0], 10);
  const length = parseInt(parts[1], 10);
  if (!sourceText || isNaN(start)) return { startLine: 0 };

  // Convert byte offset → line number
  const prefix = sourceText.slice(0, start);
  const startLine = prefix.split('\n').length;
  const segment = sourceText.slice(start, start + length);
  const endLine = startLine + (segment.match(/\n/g)?.length || 0);
  return { startLine, endLine };
}

export function normalizeMythrilOutput(
  output: MythrilGroup[],
  sourceTexts: Record<string, string> = {}
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  let idx = 0;

  for (const group of output || []) {
    for (const issue of group.issues || []) {
      const loc = issue.locations?.[0];
      const fileList = loc?.sourceList || group.sourceList || [];
      const fileName = fileList[0] || 'unknown';
      const sourceText = sourceTexts[fileName] || sourceTexts[Object.keys(sourceTexts)[0]];

      const lines = parseSourceMap(loc?.sourceMap || '', sourceText);

      const location: SourceLocation = {
        file: fileName,
        startLine: lines.startLine,
        endLine: lines.endLine,
      };

      findings.push({
        id: `mythril_${idx++}`,
        tool: 'mythril',
        detectorId: issue.swcID,
        category: categorize(issue.swcID),
        severity: mapSeverity(issue.swcID, issue.severity),
        // Mythril doesn't expose confidence in jsonv2; symbolic exec is
        // generally high-confidence, but we mark medium to be conservative
        // when output didn't include test cases.
        confidence: issue.extra?.testCases?.length ? 'high' : 'medium',
        title: issue.swcTitle,
        description: `${issue.description.head} ${issue.description.tail}`.trim(),
        swcId: issue.swcID,
        location,
        raw: issue,
      });
    }
  }

  return findings;
}

function categorize(swc: string): string {
  const map: Record<string, string> = {
    'SWC-101': 'arithmetic',
    'SWC-104': 'unchecked-call',
    'SWC-105': 'access-control',
    'SWC-106': 'access-control',
    'SWC-107': 'reentrancy',
    'SWC-112': 'delegatecall',
    'SWC-115': 'access-control',
    'SWC-116': 'time-dependence',
    'SWC-120': 'randomness',
    'SWC-127': 'assembly',
    'SWC-128': 'arithmetic',
  };
  return map[swc] || 'other';
}
