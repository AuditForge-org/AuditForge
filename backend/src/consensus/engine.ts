/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Consensus Engine
 *
 * The job: take raw findings from N tools, cluster the ones that describe
 * the same underlying issue, and produce ConsensusFindings with trust
 * signals (how many tools agreed, severity disagreements, etc.).
 *
 * Why clustering is hard:
 *   - Different tools name the same bug differently (Slither calls it
 *     'reentrancy-eth', Solhint calls it 'reentrancy', Mythril uses 'SWC-107')
 *   - Line numbers may differ by ±2 because tools point at different
 *     parts of the same statement (call site vs return vs declaration)
 *   - Multiple distinct bugs can exist on adjacent lines
 *
 * Strategy: cluster by (normalized_category, file, line_window).
 *   - normalized_category comes from SWC ID when available, else from
 *     a category synonym table
 *   - line_window groups findings within ±LINE_TOLERANCE of each other
 *
 * Trust signals output:
 *   - toolCount:           # of distinct tools that detected
 *   - consensusConfidence: derived from toolCount and individual confidences
 *   - severityDisagreement: when tools disagree on severity, we surface it
 */

import {
  NormalizedFinding,
  ConsensusFinding,
  Severity,
  Confidence,
  Tool,
  SourceLocation,
} from '../types/finding';

const LINE_TOLERANCE = 3;

/** Normalize finding category across tools so cross-tool clustering works. */
const CATEGORY_ALIASES: Record<string, string> = {
  // SWC → canonical category
  'SWC-101': 'arithmetic',
  'SWC-103': 'compiler-version',
  'SWC-104': 'unchecked-call',
  'SWC-105': 'access-control',
  'SWC-106': 'access-control',
  'SWC-107': 'reentrancy',
  'SWC-112': 'delegatecall',
  'SWC-115': 'access-control-tx-origin',
  'SWC-116': 'time-dependence',
  'SWC-118': 'access-control',
  'SWC-119': 'shadowing',
  'SWC-120': 'randomness',
  'SWC-127': 'assembly',
  'SWC-128': 'arithmetic',
  'SWC-129': 'naming',
  // Detector aliases
  'reentrancy-eth': 'reentrancy',
  'reentrancy-no-eth': 'reentrancy',
  'reentrancy-benign': 'reentrancy',
  'reentrancy-events': 'reentrancy',
  'reentrancy-state-change-after-external-call': 'reentrancy',
  'tx-origin': 'access-control-tx-origin',
  'use-of-tx-origin': 'access-control-tx-origin',
  'timestamp': 'time-dependence',
  'block-timestamp-deadline': 'time-dependence',
  'weak-prng': 'randomness',
  'arbitrary-send-eth': 'unprotected-send',
  'controlled-delegatecall': 'delegatecall',
  'delegate-call-on-uninitialized-storage-pointer': 'delegatecall',
  'suicidal': 'selfdestruct',
  'avoid-suicide': 'selfdestruct',
  'unprotected-init-function': 'unprotected-init',
  'unprotected-upgrade': 'unprotected-init',
};

function canonicalCategory(f: NormalizedFinding): string {
  // 1. SWC id is the strongest signal — same SWC = same bug class
  if (f.swcId && CATEGORY_ALIASES[f.swcId]) return CATEGORY_ALIASES[f.swcId];
  // 2. Tool-specific detector id mapped to canonical
  if (CATEGORY_ALIASES[f.detectorId]) return CATEGORY_ALIASES[f.detectorId];
  // 3. Fall back to the category field
  return f.category;
}

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
const CONFIDENCE_RANK: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

function maxSeverity(sevs: Severity[]): Severity {
  return sevs.reduce((a, b) => (SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b));
}

/**
 * Re-classify linter / pure-style findings so a cosmetic rule can never
 * masquerade as a security severity. Solhint (category 'lint') is a style
 * tool — its findings are capped at 'low', and known cosmetic rules drop to
 * 'info'. This keeps things like "no-inline-assembly" out of the medium/high
 * tiers, where they badly distort the score.
 */
const STYLE_RULES = new Set([
  'no-inline-assembly', 'reason-string', 'no-empty-blocks', 'compiler-version',
  'func-visibility', 'no-unused-vars', 'no-unused-import', 'imports-on-top',
  'max-line-length', 'quotes', 'ordering', 'visibility-modifier-order',
  'const-name-snakecase', 'contract-name-camelcase', 'var-name-mixedcase',
  'func-name-mixedcase', 'event-name-camelcase', 'modifier-name-mixedcase',
  'no-global-import', 'explicit-types', 'named-parameters-mapping',
  'immutable-vars-naming', 'payable-fallback', 'not-rely-on-time', 'no-console',
]);

function normalizeSeverity(f: NormalizedFinding): Severity {
  const id = (f.detectorId || '').toLowerCase();
  const title = (f.title || '').toLowerCase();
  if (STYLE_RULES.has(id) || title.includes('inline assembly') ||
      title.includes('naming') || title.includes('compiler version') ||
      title.includes('reason string')) {
    return 'info';
  }
  // A linter is not a security scanner — never let solhint drive medium/high.
  if ((f.category || '').toLowerCase() === 'lint' && SEVERITY_RANK[f.severity] > SEVERITY_RANK.low) {
    return 'low';
  }
  return f.severity;
}

/**
 * Confidence derivation:
 *   3+ tools agree                  → high
 *   2 tools agree                   → high if both individually high, else medium
 *   1 tool, individual confidence=high → medium
 *   1 tool, individual confidence<high → low
 *
 * Single-tool findings are deliberately downgraded — that's the whole point
 * of multi-engine auditing.
 *
 * EXCEPTION: Echidna findings stay high-confidence even when single-tool,
 * because a property-violation counterexample is a *proof*, not a heuristic.
 * The other tools genuinely can't produce this kind of finding.
 */
function deriveConfidence(findings: NormalizedFinding[]): Confidence {
  const toolCount = new Set(findings.map(f => f.tool)).size;

  // Echidna exception: any cluster containing an echidna finding is high-confidence
  if (findings.some(f => f.tool === 'echidna')) return 'high';

  if (toolCount >= 3) return 'high';
  if (toolCount === 2) {
    const allHigh = findings.every(f => f.confidence === 'high');
    return allHigh ? 'high' : 'medium';
  }
  // toolCount === 1
  return findings[0].confidence === 'high' ? 'medium' : 'low';
}

/**
 * Reduce a reported file path to its basename. Engines report the same file
 * differently — Slither may say `contracts/Vault.sol`, Mythril `/input/Vault.sol`,
 * Solhint `Vault.sol` — so comparing full paths would stop the SAME bug from two
 * tools from clustering, silently defeating consensus. Comparing basenames fixes
 * that. (Trade-off: two different files sharing a basename in different dirs could
 * over-merge, but that's rare and further constrained by category + line window,
 * and most audits here are single flattened files anyway.)
 */
function baseName(p: string | undefined | null): string {
  if (!p) return '';
  return String(p).replace(/\\/g, '/').split('/').filter(Boolean).pop() || '';
}

/**
 * Two findings cluster together when:
 *   1. Their canonical categories match exactly
 *   2. They're in the same file (compared by basename — see baseName())
 *   3. Their line numbers are within LINE_TOLERANCE
 */
function isSameCluster(a: NormalizedFinding, b: NormalizedFinding): boolean {
  if (canonicalCategory(a) !== canonicalCategory(b)) return false;
  if (baseName(a.location.file) !== baseName(b.location.file)) return false;
  return Math.abs(a.location.startLine - b.location.startLine) <= LINE_TOLERANCE;
}

interface Cluster {
  findings: NormalizedFinding[];
  category: string;
}

function clusterFindings(findings: NormalizedFinding[]): Cluster[] {
  const clusters: Cluster[] = [];
  for (const f of findings) {
    const cat = canonicalCategory(f);
    let placed = false;
    for (const c of clusters) {
      if (c.findings.some(existing => isSameCluster(existing, f))) {
        c.findings.push(f);
        placed = true;
        break;
      }
    }
    if (!placed) clusters.push({ findings: [f], category: cat });
  }
  return clusters;
}

function pickPrimary(findings: NormalizedFinding[]): NormalizedFinding {
  // Prefer tools in order of expected quality:
  //   Echidna (concrete counterexample) > Slither > Aderyn > Mythril > Semgrep > Solhint
  // Within tools, prefer the higher-severity entry.
  const TOOL_RANK: Record<Tool, number> = {
    echidna: 5,
    slither: 4,
    aderyn: 3,
    mythril: 2,
    semgrep: 1,
    solhint: 0,
  };
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return TOOL_RANK[b.tool] - TOOL_RANK[a.tool];
  })[0];
}

function detectSeverityDisagreement(
  findings: NormalizedFinding[]
): ConsensusFinding['severityDisagreement'] {
  const byTool: Record<string, Severity> = {};
  for (const f of findings) byTool[f.tool] = f.severity;
  const uniqueSeverities = new Set(Object.values(byTool));
  if (uniqueSeverities.size <= 1) return undefined;

  const sevList = Array.from(uniqueSeverities)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a]);

  return {
    reported: byTool as Record<Tool, Severity>,
    notes: `Tools disagreed on severity (${sevList.join(' / ')}). Report uses the highest classification — review individual tool outputs for context.`,
  };
}

export interface ConsensusOptions {
  /** Tools whose single-tool findings should be excluded entirely (default: none) */
  excludeSingleToolFrom?: Tool[];
  /** Minimum tool count to include (default: 1) */
  minToolCount?: number;
}

export function buildConsensus(
  findings: NormalizedFinding[],
  opts: ConsensusOptions = {}
): ConsensusFinding[] {
  const clusters = clusterFindings(findings);
  const consensus: ConsensusFinding[] = [];

  for (let i = 0; i < clusters.length; i++) {
    const cluster = clusters[i];
    const toolSet = new Set(cluster.findings.map(f => f.tool));
    const toolCount = toolSet.size;

    // Filtering
    if (opts.minToolCount && toolCount < opts.minToolCount) continue;
    if (opts.excludeSingleToolFrom && toolCount === 1) {
      if (opts.excludeSingleToolFrom.includes(cluster.findings[0].tool)) continue;
    }

    const primary = pickPrimary(cluster.findings);
    const severity = maxSeverity(cluster.findings.map(normalizeSeverity));
    const swcId = cluster.findings.map(f => f.swcId).find(Boolean);
    const cweId = cluster.findings.map(f => f.cweId).find(Boolean);

    const relatedLocations: SourceLocation[] = cluster.findings
      .filter(f => f !== primary)
      .map(f => f.location);

    consensus.push({
      id: `consensus_${i}`,
      tools: Array.from(toolSet).sort() as Tool[],
      toolCount,
      severity,
      severityDisagreement: detectSeverityDisagreement(cluster.findings),
      consensusConfidence: deriveConfidence(cluster.findings),
      category: cluster.category,
      title: primary.title,
      description: primary.description,
      swcId,
      cweId,
      location: primary.location,
      relatedLocations: relatedLocations.length > 0 ? relatedLocations : undefined,
      recommendation: primary.recommendation,
      underlying: cluster.findings,
    });
  }

  // Sort: severity desc, then toolCount desc
  consensus.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.toolCount - a.toolCount;
  });

  return consensus;
}

/**
 * Score formula — confidence-weighted and false-positive-resilient.
 *
 *   penalty(finding) = base_weight[severity] × confidence_multiplier
 *
 *   confidence_multiplier (how much we trust the finding is real):
 *     1 engine:  0.20   ← single-engine findings are the dominant FP source,
 *                          so they barely move the score; they're still SHOWN
 *                          in the report for manual triage.
 *     2 engines: 0.70
 *     3+ engines: 1.00   ← independent agreement = trusted; full weight.
 *     echidna:    1.00   ← a property counterexample is a proof, not a heuristic.
 *
 *   Aggregation uses DIMINISHING RETURNS per (severity, category): the same
 *   kind of issue repeated N times (e.g. one "centralization" note per admin
 *   function) decays — the 1st counts fully, the 2nd ×0.55, the 3rd ×0.55², …
 *   So a contract can't be tanked by a thousand identical low-severity notes,
 *   while genuinely distinct issues each count.
 *
 * Net effect: one confirmed multi-engine critical (−35) hurts a lot; a pile of
 * single-engine / lint / repeated-category noise barely registers.
 */
const BASE_WEIGHTS: Record<Severity, number> = {
  critical: 35,
  high:     15,
  medium:   5,
  low:      1.5,
  info:     0,
};
const DECAY = 0.55;

function confidenceMultiplier(c: ConsensusFinding): number {
  if (c.tools.includes('echidna')) return 1.0;   // counterexample = proof
  if (c.toolCount >= 3) return 1.0;
  if (c.toolCount === 2) return 0.7;
  return 0.2;                                     // single engine → likely FP
}

export function calculateScore(consensus: ConsensusFinding[]): { score: number; grade: string } {
  // Bucket per-finding penalties by (severity, category) so repeats of the
  // same kind of issue decay instead of summing linearly.
  const groups = new Map<string, number[]>();
  for (const c of consensus) {
    const w = BASE_WEIGHTS[c.severity] * confidenceMultiplier(c);
    if (w <= 0) continue;
    const key = `${c.severity}|${c.category}`;
    const arr = groups.get(key);
    if (arr) arr.push(w); else groups.set(key, [w]);
  }

  let penalty = 0;
  for (const weights of groups.values()) {
    weights.sort((a, b) => b - a);
    for (let k = 0; k < weights.length; k++) penalty += weights[k] * Math.pow(DECAY, k);
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));

  let grade: string;
  if (score >= 90) grade = 'A · ROBUST';
  else if (score >= 75) grade = 'B · ACCEPTABLE';
  else if (score >= 55) grade = 'C · NEEDS WORK';
  else if (score >= 30) grade = 'D · HIGH RISK';
  else grade = 'F · DO NOT DEPLOY';

  return { score, grade };
}
