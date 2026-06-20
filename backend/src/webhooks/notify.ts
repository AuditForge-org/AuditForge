/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Notification dispatcher.
 *
 * Sends watch-run results to email (via SMTP/SendGrid) and Slack
 * (incoming webhook). Both are optional per project.
 *
 * For the MVP these are best-effort — failures don't fail the audit job.
 */

import { AuditReport, ConsensusFinding, Severity } from '../types/finding';
import { WatchedProject, WatchedRun } from '../db/watched';

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

function findingsAtOrAbove(consensus: ConsensusFinding[], min: Severity): ConsensusFinding[] {
  return consensus.filter(c => SEVERITY_RANK[c.severity] >= SEVERITY_RANK[min]);
}

function buildSummaryText(
  project: WatchedProject,
  run: WatchedRun,
  report: AuditReport,
  baseUrl: string
): { subject: string; plain: string; markdown: string } {
  const relevant = findingsAtOrAbove(report.consensusFindings, project.minSeverity);
  const delta = run.scoreDelta;
  const deltaStr = delta == null ? '' : (delta > 0 ? `+${delta}` : `${delta}`);
  const arrow = delta == null ? '' : delta > 0 ? '↑' : delta < 0 ? '↓' : '·';

  const subject = `[Forensiq] ${project.repo}@${run.commitSha.slice(0, 7)} · ${report.grade} · ${report.score}/100 ${arrow}${deltaStr ? ' (' + deltaStr + ')' : ''}`;

  const reportUrl = `${baseUrl}/r/${report.id}`;

  const plain = [
    `Forensiq audit complete for ${project.repo}`,
    `Commit: ${run.commitSha.slice(0, 7)}${run.commitMessage ? ' — ' + run.commitMessage.split('\n')[0] : ''}`,
    `Score: ${report.score}/100 (${report.grade})${deltaStr ? ` ${arrow}${deltaStr} vs previous` : ''}`,
    ``,
    `Findings at or above ${project.minSeverity}: ${relevant.length}`,
    ...relevant.slice(0, 10).map((f, i) =>
      `  ${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.tools.length} tools, ${f.location.file}:${f.location.startLine})`
    ),
    relevant.length > 10 ? `  ... and ${relevant.length - 10} more` : '',
    ``,
    `Full report: ${reportUrl}`,
  ].filter(Boolean).join('\n');

  const markdown = [
    `## Forensiq audit · ${project.repo}`,
    `**Commit:** \`${run.commitSha.slice(0, 7)}\`${run.commitMessage ? ` — ${run.commitMessage.split('\n')[0]}` : ''}`,
    `**Score:** ${report.score}/100 — ${report.grade}${deltaStr ? ` (${arrow}${deltaStr})` : ''}`,
    ``,
    relevant.length === 0
      ? `*No findings at or above ${project.minSeverity}.*`
      : `### Findings (${relevant.length})\n` + relevant.slice(0, 10).map((f, i) =>
          `${i + 1}. **${f.severity.toUpperCase()}** — ${f.title} _(${f.tools.length} tools, \`${f.location.file}:${f.location.startLine}\`)_`
        ).join('\n'),
    ``,
    `[View full report](${reportUrl})`,
  ].join('\n');

  return { subject, plain, markdown };
}

/**
 * Email notification. Provider-agnostic: prefers Resend (RESEND_API_KEY),
 * falls back to SendGrid (SENDGRID_API_KEY). NOTIFY_FROM_EMAIL must be a
 * sender on a domain verified with the chosen provider; it accepts either a
 * bare address or "Display Name <addr@domain>".
 */
async function sendEmail(to: string, subject: string, body: string): Promise<void> {
  const from = process.env.NOTIFY_FROM_EMAIL || 'Audit Forge <onboarding@resend.dev>';
  const resendKey = process.env.RESEND_API_KEY;
  const sendgridKey = process.env.SENDGRID_API_KEY;

  if (resendKey) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [to], subject, text: body }),
    });
    if (!res.ok) console.warn(`[notify] resend email failed: ${res.status} ${await res.text()}`);
    return;
  }

  if (sendgridKey) {
    // SendGrid wants a bare email + optional name; extract from "Name <addr>".
    const m = from.match(/<([^>]+)>/);
    const fromEmail = m ? m[1] : from;
    const fromName = m ? from.replace(/\s*<[^>]+>\s*/, '').trim() || 'Audit Forge' : 'Audit Forge';
    const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: { Authorization: `Bearer ${sendgridKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: fromEmail, name: fromName },
        subject,
        content: [{ type: 'text/plain', value: body }],
      }),
    });
    if (!res.ok) console.warn(`[notify] sendgrid email failed: ${res.status} ${await res.text()}`);
    return;
  }

  console.warn('[notify] no email provider configured (RESEND_API_KEY / SENDGRID_API_KEY), skipping email');
}

/**
 * Slack via incoming webhook. The webhook URL is per-project (stored on
 * the WatchedProject row); we just POST to it.
 */
async function sendSlack(webhookUrl: string, subject: string, markdown: string): Promise<void> {
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: subject,
      blocks: [
        {
          type: 'section',
          text: { type: 'mrkdwn', text: markdown },
        },
      ],
    }),
  });
  if (!res.ok) {
    console.warn(`[notify] slack send failed: ${res.status}`);
  }
}

export async function notifyWatchRun(
  project: WatchedProject,
  run: WatchedRun,
  report: AuditReport
): Promise<void> {
  const baseUrl = process.env.PUBLIC_URL || 'http://localhost:3000';
  const { subject, plain, markdown } = buildSummaryText(project, run, report, baseUrl);

  const tasks: Array<Promise<void>> = [];
  if (project.notifyEmail) tasks.push(sendEmail(project.notifyEmail, subject, plain));
  if (project.notifySlack) tasks.push(sendSlack(project.notifySlack, subject, markdown));

  // Fire all; log failures but don't reject (best-effort)
  await Promise.allSettled(tasks);
}
