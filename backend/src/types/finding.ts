/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Unified Finding Schema
 *
 * Every tool (Slither, Mythril, Aderyn, Semgrep, Solhint) produces output in
 * a different format. The normalizers convert each tool's native JSON into
 * this canonical schema. The consensus engine operates exclusively on this.
 *
 * Severity taxonomy follows SWC and CWE conventions:
 *   - critical: direct loss of funds, contract takeover
 *   - high:     loss of funds under specific conditions, broken invariants
 *   - medium:   issues affecting only specific users or non-fund state
 *   - low:      best-practice violations with limited impact
 *   - info:     style, gas optimization, informational
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type Tool = 'slither' | 'mythril' | 'aderyn' | 'semgrep' | 'solhint' | 'echidna';

export interface SourceLocation {
  file: string;
  startLine: number;
  endLine?: number;
  startCol?: number;
  endCol?: number;
  snippet?: string;
}

export interface NormalizedFinding {
  /** Stable identifier within this tool run */
  id: string;

  /** Which engine produced this finding */
  tool: Tool;

  /** Tool's native detector/check identifier, e.g. 'reentrancy-eth', 'SWC-107' */
  detectorId: string;

  /** Human-readable category, e.g. 'reentrancy', 'access-control' */
  category: string;

  severity: Severity;
  confidence: Confidence;

  title: string;
  description: string;

  /** Standardized cross-references where available */
  swcId?: string;   // Smart Contract Weakness Classification
  cweId?: string;   // Common Weakness Enumeration

  /** Where in the code */
  location: SourceLocation;

  /** Additional locations if the finding spans multiple lines/files */
  relatedLocations?: SourceLocation[];

  /** Concrete remediation guidance */
  recommendation?: string;

  /** Tool-specific raw payload, preserved for transparency / audit trail */
  raw?: unknown;
}

/**
 * A consensus finding is the unit the report ultimately renders.
 * Multiple NormalizedFindings (from different tools) can be merged
 * into one ConsensusFinding when they describe the same underlying issue.
 */
export interface ConsensusFinding {
  id: string;

  /** Tools that detected this issue */
  tools: Tool[];

  /** Number of tools agreeing — primary trust signal */
  toolCount: number;

  /** Reconciled severity (max of reported severities) */
  severity: Severity;

  /** Disagreement metadata — null if all tools agreed on severity */
  severityDisagreement?: {
    reported: Record<Tool, Severity>;
    notes: string;
  };

  /** Confidence based on tool count and individual confidences */
  consensusConfidence: Confidence;

  category: string;
  title: string;
  description: string;

  swcId?: string;
  cweId?: string;

  location: SourceLocation;
  relatedLocations?: SourceLocation[];

  recommendation?: string;

  /** All underlying findings that were clustered into this consensus item */
  underlying: NormalizedFinding[];
}

export interface AuditReport {
  id: string;
  createdAt: string;
  /** User who submitted this audit. Undefined for anonymous submissions. */
  ownerId?: string;

  source: {
    type: 'paste' | 'address' | 'github';
    label: string;
    address?: string;
    chain?: string;
    repo?: string;
    path?: string;
    ref?: string;
  };

  contract: {
    /** Flattened or single-file source code */
    code: string;
    lines: number;
    solcVersion?: string;
  };

  /** Tools that successfully ran */
  toolsRun: Tool[];

  /** Tools that failed or were unavailable, with reasons */
  toolErrors: Array<{ tool: Tool; error: string }>;

  /** Raw findings before consensus clustering */
  rawFindings: NormalizedFinding[];

  /** The consensus-clustered findings — what users actually see */
  consensusFindings: ConsensusFinding[];

  /** 0-100 score based on consensus findings only */
  score: number;
  grade: string;

  /** AI auditor brief (Claude) */
  aiBrief?: string;

  /** Total scan duration in ms */
  durationMs: number;
}
