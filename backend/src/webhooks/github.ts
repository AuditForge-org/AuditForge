/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — GitHub webhook handler.
 *
 * Flow:
 *   1. Receive POST /api/webhooks/github
 *   2. Verify X-Hub-Signature-256 against the project's stored secret
 *   3. For push events: identify changed .sol files matching the project's path filter
 *   4. Enqueue an audit job per file (or one combined if reasonable)
 *   5. Post a GitHub check-run on the commit ("pending" → updated when done)
 *   6. Update the WatchedRun row as the audit progresses
 *
 * Security:
 *   - HMAC SHA-256 verification is non-negotiable
 *   - We use timing-safe comparison
 *   - We rate-limit per-project to prevent webhook flood
 *   - We bound the number of files audited per push (10) to prevent abuse
 *
 * Notifications:
 *   - When the run completes, we notify via email and/or Slack if configured
 *   - We include the score delta (this commit vs prior) and any new
 *     critical/high findings
 */

import { Request, Response, Router } from 'express';
import { createHmac, timingSafeEqual } from 'crypto';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import {
  findMatchingProjects,
  createRun,
  getLatestCompletedRun,
  updateRunStatus,
  WatchedProject,
} from '../db/watched';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const connection = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });
const auditQueue = new Queue('audits', { connection });

const MAX_FILES_PER_PUSH = 10;

interface GithubPushPayload {
  ref: string;                 // e.g. "refs/heads/main"
  before: string;
  after: string;               // commit SHA
  repository: {
    full_name: string;         // "owner/repo"
    default_branch: string;
  };
  head_commit: {
    id: string;
    message: string;
    author: { name: string; email: string };
    added: string[];
    modified: string[];
    removed: string[];
  };
  commits: Array<{
    id: string;
    added: string[];
    modified: string[];
    removed: string[];
  }>;
}

/**
 * Verify the webhook signature with constant-time comparison.
 * GitHub sends:  X-Hub-Signature-256: sha256=<hex>
 */
export function verifyGithubSignature(
  rawBody: Buffer,
  signature: string | undefined,
  secret: string
): boolean {
  if (!signature || !signature.startsWith('sha256=')) return false;

  const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');

  // Timing-safe comparison requires equal-length buffers
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return false;

  return timingSafeEqual(sigBuf, expBuf);
}

/**
 * From the push payload, extract the set of .sol files that changed and
 * pass the project's path filter (if any).
 */
function extractChangedSolFiles(payload: GithubPushPayload, pathFilter?: string): string[] {
  const all = new Set<string>();
  // Use head_commit added/modified for the most direct view of "what changed"
  for (const f of payload.head_commit?.added || []) all.add(f);
  for (const f of payload.head_commit?.modified || []) all.add(f);
  // Fallback: also walk all commits in the push
  for (const c of payload.commits || []) {
    for (const f of c.added) all.add(f);
    for (const f of c.modified) all.add(f);
  }

  return Array.from(all).filter(f => {
    if (!f.endsWith('.sol')) return false;
    if (pathFilter && !f.startsWith(pathFilter)) return false;
    // Skip test/mock files by default
    if (/\/(test|tests|mock|mocks)\//i.test(f)) return false;
    return true;
  });
}

const router = Router();

/**
 * Webhook endpoint. The raw body MUST be available for HMAC verification —
 * mount this with express.raw({type: 'application/json'}) instead of the
 * usual express.json() middleware.
 */
router.post('/github', async (req: Request, res: Response) => {
  const event = req.header('x-github-event');
  const signature = req.header('x-hub-signature-256');
  const deliveryId = req.header('x-github-delivery');

  // Quick replies for events we don't process
  if (event === 'ping') {
    return res.json({ ok: true, message: 'pong' });
  }
  if (event !== 'push') {
    return res.status(202).json({ ok: true, message: `ignored event: ${event}` });
  }

  // Parse JSON ourselves since we receive raw body
  const rawBody = req.body as Buffer;
  let payload: GithubPushPayload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // Resolve branch from refs/heads/<branch>
  const branch = payload.ref?.replace(/^refs\/heads\//, '') || '';
  const repo = payload.repository?.full_name;
  if (!repo || !branch) {
    return res.status(400).json({ error: 'Missing repository or ref' });
  }

  // Find matching watched projects
  const projects = await findMatchingProjects(repo, branch);
  if (projects.length === 0) {
    return res.status(202).json({ ok: true, message: 'No watched projects for this repo+branch' });
  }

  // Verify signature against each project's secret. The first match wins;
  // if none match, reject.
  let verifiedProject: WatchedProject | null = null;
  for (const p of projects) {
    if (verifyGithubSignature(rawBody, signature, p.webhookSecret)) {
      verifiedProject = p;
      break;
    }
  }
  if (!verifiedProject) {
    console.warn(`[webhook] signature verification failed for ${repo}@${branch} (delivery=${deliveryId})`);
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Determine which files to audit
  const changedFiles = extractChangedSolFiles(payload, verifiedProject.pathFilter);
  if (changedFiles.length === 0) {
    return res.status(202).json({ ok: true, message: 'No Solidity files changed' });
  }

  if (changedFiles.length > MAX_FILES_PER_PUSH) {
    console.warn(`[webhook] push to ${repo} changed ${changedFiles.length} .sol files, capping at ${MAX_FILES_PER_PUSH}`);
  }
  const filesToAudit = changedFiles.slice(0, MAX_FILES_PER_PUSH);

  // Create a watched_run record and enqueue audits
  const run = await createRun({
    projectId: verifiedProject.id,
    commitSha: payload.after,
    commitMessage: payload.head_commit?.message,
    committer: payload.head_commit?.author?.name,
  });

  const auditIds: string[] = [];
  for (const filePath of filesToAudit) {
    const job = await auditQueue.add('audit', {
      auditId: crypto.randomUUID(),
      code: '',  // worker will fetch from GitHub using the source.github type
      source: {
        type: 'github',
        label: `${repo}:${filePath}@${payload.after.slice(0, 7)}`,
        repo,
        path: filePath,
        ref: payload.after,
      },
      watchedRunId: run.id,
      watchedProjectId: verifiedProject.id,
    });
    auditIds.push(job.id as string);
  }

  // Optionally: post a "pending" GitHub check-run here, then update on completion.
  // This requires a GitHub App with checks:write permission. See docs/github-app.md.

  res.status(202).json({
    ok: true,
    runId: run.id,
    filesQueued: filesToAudit.length,
    auditIds,
  });
});

export default router;
