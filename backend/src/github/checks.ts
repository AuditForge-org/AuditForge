/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — GitHub App API operations.
 *
 * The two things we do with the App credentials beyond fetching source:
 *
 *   1. Check runs: appear next to the commit / PR. Render as red ✗ or
 *      green ✓ in the GitHub UI. Have a full markdown body with findings,
 *      score, and a deep link to the Forensiq report.
 *
 *   2. PR comments: post inline review comments on the specific lines
 *      where issues were detected. Limited to changed lines (you can't
 *      comment on lines that aren't in the PR diff).
 *
 * Both are best-effort. Failures are logged but don't fail the audit.
 */

import { getInstallationToken } from './auth';
import { AuditReport, ConsensusFinding, Severity } from '../types/finding';

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

// ─── Check runs ──────────────────────────────────────────────────────

type CheckConclusion =
  | 'success' | 'failure' | 'neutral' | 'cancelled' | 'timed_out' | 'action_required';

interface CreateCheckRunBody {
  name: string;
  head_sha: string;
  status: 'queued' | 'in_progress' | 'completed';
  conclusion?: CheckConclusion;
  started_at?: string;
  completed_at?: string;
  output?: {
    title: string;
    summary: string;
    text?: string;
    annotations?: CheckAnnotation[];
  };
  details_url?: string;
  external_id?: string;
}

interface CheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  start_column?: number;
  end_column?: number;
  annotation_level: 'notice' | 'warning' | 'failure';
  message: string;
  title?: string;
  raw_details?: string;
}

async function githubRequest(
  installationId: number,
  method: string,
  path: string,
  body?: unknown
): Promise<unknown> {
  const token = await getInstallationToken(installationId);
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'forensiq-github-app',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`GitHub ${method} ${path} failed: ${res.status} ${errBody}`);
  }
  return res.json();
}

/**
 * Translate consensus findings into GitHub check annotations. GitHub caps
 * each request at 50 annotations — for more, send multiple update calls.
 *
 * Severity mapping:
 *   critical, high  → 'failure'  (red, fails the check)
 *   medium          → 'warning'  (yellow)
 *   low, info       → 'notice'   (gray, informational)
 */
function findingsToAnnotations(findings: ConsensusFinding[]): CheckAnnotation[] {
  return findings
    .filter(f => f.location.startLine > 0)
    .slice(0, 50)
    .map(f => ({
      path: f.location.file,
      start_line: f.location.startLine,
      end_line: f.location.endLine ?? f.location.startLine,
      annotation_level:
        SEVERITY_RANK[f.severity] >= 3 ? 'failure' :
        SEVERITY_RANK[f.severity] === 2 ? 'warning' : 'notice',
      title: `[${f.severity.toUpperCase()}] ${f.title}`,
      message: f.description.slice(0, 600),
      raw_details: [
        `Detected by: ${f.tools.join(', ')} (${f.toolCount} tool${f.toolCount > 1 ? 's' : ''})`,
        f.swcId ? `Reference: ${f.swcId}` : '',
        f.recommendation ? `\nRecommendation:\n${f.recommendation}` : '',
      ].filter(Boolean).join('\n'),
    }));
}

function determineConclusion(report: AuditReport): CheckConclusion {
  const hasCritical = report.consensusFindings.some(f => f.severity === 'critical');
  const hasHigh = report.consensusFindings.some(f => f.severity === 'high');
  if (hasCritical) return 'failure';
  if (hasHigh) return 'action_required';
  return 'success';
}

function buildCheckSummary(report: AuditReport, scoreDelta?: number): string {
  const counts = countBySeverity(report.consensusFindings);
  const lines = [
    `**Score: ${report.score}/100** — ${report.grade}`,
    scoreDelta != null ? `Delta vs previous: **${scoreDelta > 0 ? '+' : ''}${scoreDelta}**` : '',
    '',
    `**Findings**`,
    counts.critical ? `- 🟥 ${counts.critical} critical` : '',
    counts.high     ? `- 🟧 ${counts.high} high`         : '',
    counts.medium   ? `- 🟦 ${counts.medium} medium`     : '',
    counts.low      ? `- 🟪 ${counts.low} low`           : '',
    counts.info     ? `- ⬜ ${counts.info} info`         : '',
    '',
    `**Tools that ran:** ${report.toolsRun.join(', ')}`,
    report.toolErrors.length ? `\n**Tools that errored:** ${report.toolErrors.map(e => e.tool).join(', ')}` : '',
  ];
  return lines.filter(Boolean).join('\n');
}

function buildCheckDetailText(report: AuditReport): string {
  // Top findings, one per line, capped to keep under GitHub's 65k char limit
  const top = [...report.consensusFindings]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    .slice(0, 20);

  const lines = [
    '### Top findings',
    '',
    '| # | Severity | Title | Tools | Location |',
    '|---|----------|-------|-------|----------|',
    ...top.map((f, i) =>
      `| ${i + 1} | ${f.severity.toUpperCase()} | ${escapeMd(f.title)} | ${f.toolCount} (${f.tools.join('+')}) | \`${f.location.file}:${f.location.startLine}\` |`
    ),
  ];

  if (report.aiBrief) {
    lines.push('', '### Auditor brief', '', report.aiBrief.slice(0, 4000));
  }

  return lines.join('\n');
}

function escapeMd(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

function countBySeverity(findings: ConsensusFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

// ─── Public API ──────────────────────────────────────────────────────

export interface CreateCheckRunOpts {
  installationId: number;
  owner: string;
  repo: string;
  headSha: string;
  detailsUrl: string;
  externalId?: string;
}

/**
 * Create a "queued" check run as soon as the webhook fires — so the GitHub
 * UI shows "Forensiq audit pending" while the actual scan runs.
 * Returns the check run id, which we use to update on completion.
 */
export async function createPendingCheckRun(opts: CreateCheckRunOpts): Promise<number> {
  const body: CreateCheckRunBody = {
    name: 'Forensiq audit',
    head_sha: opts.headSha,
    status: 'in_progress',
    started_at: new Date().toISOString(),
    details_url: opts.detailsUrl,
    external_id: opts.externalId,
    output: {
      title: 'Running multi-engine audit…',
      summary: 'Slither, Aderyn, Mythril, Semgrep and Solhint are analyzing the changed files. This usually takes 1-3 minutes.',
    },
  };

  const res = (await githubRequest(
    opts.installationId, 'POST',
    `/repos/${opts.owner}/${opts.repo}/check-runs`,
    body
  )) as { id: number };

  return res.id;
}

export interface CompleteCheckRunOpts {
  installationId: number;
  owner: string;
  repo: string;
  checkRunId: number;
  report: AuditReport;
  detailsUrl: string;
  scoreDelta?: number;
}

export async function completeCheckRun(opts: CompleteCheckRunOpts): Promise<void> {
  const { installationId, owner, repo, checkRunId, report, detailsUrl, scoreDelta } = opts;
  const annotations = findingsToAnnotations(report.consensusFindings);
  const conclusion = determineConclusion(report);

  const body: Partial<CreateCheckRunBody> = {
    status: 'completed',
    conclusion,
    completed_at: new Date().toISOString(),
    details_url: detailsUrl,
    output: {
      title: `Score ${report.score}/100 · ${report.grade}`,
      summary: buildCheckSummary(report, scoreDelta),
      text: buildCheckDetailText(report),
      // First 50 annotations attached here. Additional batches come below.
      annotations: annotations.slice(0, 50),
    },
  };

  await githubRequest(
    installationId, 'PATCH',
    `/repos/${owner}/${repo}/check-runs/${checkRunId}`,
    body
  );

  // GitHub caps at 50 annotations per request — send rest in followup updates.
  for (let i = 50; i < annotations.length; i += 50) {
    await githubRequest(
      installationId, 'PATCH',
      `/repos/${owner}/${repo}/check-runs/${checkRunId}`,
      { output: { title: body.output!.title, summary: body.output!.summary, annotations: annotations.slice(i, i + 50) } }
    );
  }
}

/**
 * Mark a check run as failed (used when the audit itself errors out,
 * not when it finds issues).
 */
export async function failCheckRun(opts: {
  installationId: number;
  owner: string;
  repo: string;
  checkRunId: number;
  reason: string;
}): Promise<void> {
  await githubRequest(
    opts.installationId, 'PATCH',
    `/repos/${opts.owner}/${opts.repo}/check-runs/${opts.checkRunId}`,
    {
      status: 'completed',
      conclusion: 'cancelled',
      completed_at: new Date().toISOString(),
      output: {
        title: 'Forensiq audit failed',
        summary: opts.reason.slice(0, 600),
      },
    }
  );
}

// ─── PR comments ─────────────────────────────────────────────────────

export interface PostPrCommentOpts {
  installationId: number;
  owner: string;
  repo: string;
  prNumber: number;
  report: AuditReport;
  detailsUrl: string;
  scoreDelta?: number;
}

/**
 * Post (or update) a single overview comment on the PR. We use a magic
 * marker in the body to recognize Forensiq's own comments and update them
 * in place rather than spamming the PR on every push.
 */
const COMMENT_MARKER = '<!-- forensiq-audit-comment -->';

export async function upsertPrComment(opts: PostPrCommentOpts): Promise<void> {
  const { installationId, owner, repo, prNumber, report, detailsUrl, scoreDelta } = opts;

  const body = [
    COMMENT_MARKER,
    `## 🔎 Forensiq audit · Score ${report.score}/100 · ${report.grade}`,
    scoreDelta != null
      ? `**Delta vs main:** ${scoreDelta > 0 ? '+' : ''}${scoreDelta}`
      : '',
    '',
    buildCheckSummary(report, scoreDelta).replace(/^\*\*Score:.+$/m, '').trim(),
    '',
    buildCheckDetailText(report).slice(0, 30_000),
    '',
    `[View full report on Forensiq →](${detailsUrl})`,
  ].filter(Boolean).join('\n');

  // Find existing Forensiq comment
  const existing = (await githubRequest(
    installationId, 'GET',
    `/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100`
  )) as Array<{ id: number; body: string }>;

  const ours = existing.find(c => c.body.includes(COMMENT_MARKER));

  if (ours) {
    await githubRequest(
      installationId, 'PATCH',
      `/repos/${owner}/${repo}/issues/comments/${ours.id}`,
      { body }
    );
  } else {
    await githubRequest(
      installationId, 'POST',
      `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
      { body }
    );
  }
}
