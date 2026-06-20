/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Semgrep + Solhint normalizers.
 *
 * Semgrep with the smart-contracts ruleset
 * (https://semgrep.dev/p/smart-contracts) provides pattern-matching
 * detection. Solhint catches style + linting issues that occasionally
 * indicate real bugs.
 *
 * Both are noisy compared to Slither/Mythril and contribute mostly to
 * confidence weighting in the consensus engine rather than producing
 * unique findings.
 */

import { NormalizedFinding, Severity, Confidence, SourceLocation } from '../types/finding';

// ─── SEMGREP ─────────────────────────────────────────────────────────────

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: 'ERROR' | 'WARNING' | 'INFO';
    metadata?: {
      category?: string;
      cwe?: string | string[];
      'swc-id'?: string;
      references?: string[];
    };
    lines?: string;
  };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors?: unknown[];
}

function mapSemgrepSeverity(sev: SemgrepResult['extra']['severity'], checkId: string): Severity {
  const id = checkId.toLowerCase();
  // Promote known dangerous patterns
  if (id.includes('reentrancy') || id.includes('delegatecall') || id.includes('selfdestruct')) {
    return sev === 'ERROR' ? 'critical' : 'high';
  }
  switch (sev) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'info';
  }
}

export function normalizeSemgrepOutput(output: SemgrepOutput): NormalizedFinding[] {
  if (!output?.results) return [];

  return output.results.map((r, i): NormalizedFinding => {
    const cwe = Array.isArray(r.extra.metadata?.cwe)
      ? r.extra.metadata?.cwe[0]
      : r.extra.metadata?.cwe;

    return {
      id: `semgrep_${i}`,
      tool: 'semgrep',
      detectorId: r.check_id,
      category: r.extra.metadata?.category || categorizeFromCheck(r.check_id),
      severity: mapSemgrepSeverity(r.extra.severity, r.check_id),
      confidence: 'medium', // Pattern matching → moderate confidence
      title: prettifyCheckId(r.check_id),
      description: r.extra.message,
      swcId: r.extra.metadata?.['swc-id'],
      cweId: cwe,
      location: {
        file: r.path,
        startLine: r.start.line,
        endLine: r.end.line,
        startCol: r.start.col,
        endCol: r.end.col,
        snippet: r.extra.lines,
      },
      raw: r,
    };
  });
}

function prettifyCheckId(id: string): string {
  const last = id.split('.').pop() || id;
  return last.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function categorizeFromCheck(id: string): string {
  const low = id.toLowerCase();
  if (low.includes('reentr')) return 'reentrancy';
  if (low.includes('delegate')) return 'delegatecall';
  if (low.includes('tx-origin') || low.includes('access')) return 'access-control';
  if (low.includes('timestamp') || low.includes('block')) return 'time-dependence';
  if (low.includes('overflow') || low.includes('underflow')) return 'arithmetic';
  return 'other';
}

// ─── SOLHINT ─────────────────────────────────────────────────────────────

// solhint 5.x `-f json` emits a FLAT array of issue objects (severity as the
// string "Error"/"Warning"), terminated by a {"conclusion": "..."} summary
// object. Older solhint nested issues under {filePath, reports:[...]} with a
// numeric severity (1=warning, 2=error). We accept both shapes.
interface SolhintIssue {
  line: number;
  column: number;
  severity: number | string;
  message: string;
  ruleId?: string;
  filePath?: string;
  conclusion?: string;
  reports?: SolhintIssue[];
}

function solhintSeverityNum(sev: number | string): number {
  if (typeof sev === 'number') return sev;
  return /error/i.test(sev) ? 2 : 1;
}

function mapSolhintSeverity(sev: number, ruleId: string): Severity {
  const r = ruleId.toLowerCase();
  if (r === 'avoid-tx-origin' || r === 'avoid-call-value' || r === 'no-inline-assembly') {
    return sev === 2 ? 'high' : 'medium';
  }
  if (r.includes('security')) {
    return sev === 2 ? 'high' : 'medium';
  }
  // Most solhint rules are style/best-practice → low or info
  return sev === 2 ? 'low' : 'info';
}

const SOLHINT_TO_SLITHER: Record<string, string> = {
  'avoid-tx-origin': 'tx-origin',
  'avoid-call-value': 'low-level-calls',
  'reentrancy': 'reentrancy-eth',
  'avoid-low-level-calls': 'low-level-calls',
  'avoid-sha3': 'incorrect-shift',
  'avoid-suicide': 'suicidal',
  'avoid-throw': 'pragma',
  'compiler-version': 'solc-version',
};

const SOLHINT_TO_SWC: Record<string, string> = {
  'avoid-tx-origin': 'SWC-115',
  'avoid-call-value': 'SWC-104',
  'reentrancy': 'SWC-107',
  'avoid-suicide': 'SWC-106',
  'compiler-version': 'SWC-103',
};

export function normalizeSolhintOutput(output: SolhintIssue[]): NormalizedFinding[] {
  // Flatten both the 5.x flat shape and the legacy nested shape into one list.
  const issues: Array<SolhintIssue & { _file?: string }> = [];
  for (const item of Array.isArray(output) ? output : []) {
    if (!item || item.conclusion !== undefined) continue;       // trailing summary object
    if (Array.isArray(item.reports)) {                          // legacy {filePath, reports:[]}
      for (const r of item.reports) issues.push({ ...r, _file: item.filePath });
    } else if (item.ruleId !== undefined) {                     // 5.x flat issue
      issues.push({ ...item, _file: item.filePath });
    }
  }

  return issues.map((r, i): NormalizedFinding => {
    const ruleId = r.ruleId || 'unknown';
    return {
      id: `solhint_${i}`,
      tool: 'solhint',
      detectorId: SOLHINT_TO_SLITHER[ruleId] || ruleId,
      category: 'lint',
      severity: mapSolhintSeverity(solhintSeverityNum(r.severity), ruleId),
      confidence: 'low', // Linter-level; many false positives in security context
      title: prettifyCheckId(ruleId),
      description: r.message,
      swcId: SOLHINT_TO_SWC[ruleId],
      location: {
        file: r._file || 'Contract.sol',
        startLine: r.line,
        startCol: r.column,
      },
      raw: r,
    };
  });
}
