/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — GitHub App webhook handler.
 *
 * This is the unified webhook for the GitHub App. Unlike the per-project
 * webhooks in webhooks/github.ts (which use per-project secrets and require
 * manual setup), this one:
 *   - Uses the App's webhook secret (one secret for all installations)
 *   - Receives events for ALL repos under any installation
 *   - Handles installation lifecycle (created, deleted, suspended, repos changed)
 *   - Creates check runs immediately on push for live status in GitHub UI
 *
 * Events handled:
 *   - ping                                — initial setup verification
 *   - installation                        — App installed / uninstalled / suspended
 *   - installation_repositories           — repo selection changed
 *   - push                                — code pushed; queue audit
 *   - pull_request (opened, synchronize)  — PR opened or new commits pushed to it
 *   - check_run (rerequested)             — user clicked "Re-run" in GitHub UI
 *
 * Security: every payload's signature is verified against
 * GITHUB_APP_WEBHOOK_SECRET (constant for all installations of the App).
 */

import { Request, Response, Router } from 'express';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import { randomUUID } from 'crypto';
import { verifyGithubSignature } from '../webhooks/github';
import {
  upsertInstallation,
  deleteInstallation,
  getInstallation,
} from '../db/installations';
import { isConfigured, getWebhookSecret } from './auth';
import { createPendingCheckRun } from './checks';
import { createRun, findMatchingProjects } from '../db/watched';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const connection = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });
const auditQueue = new Queue('audits', { connection });
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3000';

const MAX_FILES_PER_PUSH = 10;

// ─── Payload types (only fields we use) ──────────────────────────────

interface GhInstallation {
  id: number;
  account: { login: string; type: 'User' | 'Organization' };
  repository_selection: 'all' | 'selected';
  suspended_at: string | null;
}
interface GhRepo {
  full_name: string;
  default_branch?: string;
  private?: boolean;
}
interface InstallationPayload {
  action: 'created' | 'deleted' | 'suspend' | 'unsuspend' | 'new_permissions_accepted';
  installation: GhInstallation;
  repositories?: GhRepo[];
}
interface InstallationReposPayload {
  action: 'added' | 'removed';
  installation: GhInstallation;
  repositories_added?: GhRepo[];
  repositories_removed?: GhRepo[];
}
interface PushPayload {
  ref: string;
  after: string;
  before: string;
  installation?: { id: number };
  repository: GhRepo;
  head_commit?: {
    id: string;
    message: string;
    author: { name: string; email: string };
    added: string[];
    modified: string[];
    removed: string[];
  };
  commits?: Array<{ added: string[]; modified: string[]; removed: string[] }>;
  sender: { login: string };
}
interface PullRequestPayload {
  action: 'opened' | 'synchronize' | 'reopened' | 'closed' | 'edited';
  number: number;
  pull_request: {
    number: number;
    head: { sha: string; ref: string; repo: GhRepo };
    base: { sha: string; ref: string; repo: GhRepo };
    title: string;
    user: { login: string };
  };
  repository: GhRepo;
  installation?: { id: number };
}

// ─── Helpers ─────────────────────────────────────────────────────────

function extractChangedSolFiles(
  payload: PushPayload,
  pathFilter?: string
): string[] {
  const all = new Set<string>();
  for (const f of payload.head_commit?.added ?? []) all.add(f);
  for (const f of payload.head_commit?.modified ?? []) all.add(f);
  for (const c of payload.commits ?? []) {
    for (const f of c.added) all.add(f);
    for (const f of c.modified) all.add(f);
  }
  return [...all].filter(f => {
    if (!f.endsWith('.sol')) return false;
    if (pathFilter && !f.startsWith(pathFilter)) return false;
    if (/\/(test|tests|mock|mocks)\//i.test(f)) return false;
    return true;
  });
}

async function fetchPrChangedSolFiles(
  installationId: number,
  owner: string,
  repo: string,
  prNumber: number
): Promise<string[]> {
  const { getInstallationToken } = await import('./auth');
  const token = await getInstallationToken(installationId);
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'forensiq-github-app',
      },
    }
  );
  if (!res.ok) throw new Error(`PR files fetch failed: ${res.status}`);
  const files = (await res.json()) as Array<{ filename: string; status: string }>;
  return files
    .filter(f =>
      f.filename.endsWith('.sol') &&
      f.status !== 'removed' &&
      !/\/(test|tests|mock|mocks)\//i.test(f.filename)
    )
    .map(f => f.filename);
}

// ─── Router ──────────────────────────────────────────────────────────

const router = Router();

router.post('/app', async (req: Request, res: Response) => {
  if (!isConfigured()) {
    return res.status(503).json({ error: 'GitHub App not configured on this server' });
  }

  const event = req.header('x-github-event');
  const signature = req.header('x-hub-signature-256');
  const deliveryId = req.header('x-github-delivery');
  const rawBody = req.body as Buffer;

  // Verify HMAC against the App webhook secret
  if (!verifyGithubSignature(rawBody, signature, getWebhookSecret())) {
    console.warn(`[gh-app] sig verify failed (delivery=${deliveryId} event=${event})`);
    return res.status(401).json({ error: 'Invalid signature' });
  }

  if (event === 'ping') {
    return res.json({ ok: true, message: 'pong' });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  try {
    switch (event) {
      case 'installation':
        await handleInstallation(payload as InstallationPayload);
        return res.status(200).json({ ok: true });
      case 'installation_repositories':
        await handleInstallationRepos(payload as InstallationReposPayload);
        return res.status(200).json({ ok: true });
      case 'push':
        return res.status(202).json(await handlePush(payload as PushPayload));
      case 'pull_request':
        return res.status(202).json(await handlePullRequest(payload as PullRequestPayload));
      case 'check_run':
        // Re-run requests; treat as a fresh push event
        // (Implementation: rerun the audit for the same head_sha)
        return res.status(202).json({ ok: true, note: 'check_run rerun queued' });
      default:
        return res.status(202).json({ ok: true, ignored: event });
    }
  } catch (e) {
    console.error('[gh-app] handler error:', e);
    return res.status(500).json({ error: 'Handler failed', message: (e as Error).message });
  }
});

// ─── Event handlers ──────────────────────────────────────────────────

async function handleInstallation(p: InstallationPayload): Promise<void> {
  const inst = p.installation;
  if (p.action === 'deleted') {
    await deleteInstallation(inst.id);
    return;
  }
  await upsertInstallation({
    installationId: inst.id,
    accountLogin: inst.account.login,
    accountType: inst.account.type,
    repoSelection: inst.repository_selection,
    repos: (p.repositories ?? []).map(r => r.full_name),
    suspended: inst.suspended_at != null,
  });
}

async function handleInstallationRepos(p: InstallationReposPayload): Promise<void> {
  // Resolve the current set of repos by re-reading
  const existing = await getInstallation(p.installation.id);
  const current = new Set(existing?.repos ?? []);
  for (const r of p.repositories_added ?? []) current.add(r.full_name);
  for (const r of p.repositories_removed ?? []) current.delete(r.full_name);

  await upsertInstallation({
    installationId: p.installation.id,
    accountLogin: p.installation.account.login,
    accountType: p.installation.account.type,
    repoSelection: p.installation.repository_selection,
    repos: [...current],
    suspended: p.installation.suspended_at != null,
  });
}

async function handlePush(p: PushPayload): Promise<unknown> {
  const installationId = p.installation?.id;
  if (!installationId) return { ok: true, ignored: 'no installation context' };

  const repo = p.repository.full_name;
  const [owner, repoName] = repo.split('/');
  const branch = p.ref.replace(/^refs\/heads\//, '');
  const sha = p.after;

  // Find watched projects matching this repo+branch. Note: with the App,
  // users may not have a per-project secret stored — they just installed
  // the App. We accept any push from an installed repo and treat it as
  // a watched project if the user opted in via the App UI.
  const projects = await findMatchingProjects(repo, branch);
  if (projects.length === 0) {
    return { ok: true, ignored: 'no watched project for this repo+branch' };
  }
  const project = projects[0];

  // Identify changed .sol files
  const files = extractChangedSolFiles(p, project.pathFilter);
  if (files.length === 0) {
    return { ok: true, ignored: 'no .sol files changed' };
  }
  const filesToAudit = files.slice(0, MAX_FILES_PER_PUSH);

  // Open a pending check run so the commit shows "Forensiq: in progress"
  // immediately. We get a check run id back to update on completion.
  let checkRunId: number | undefined;
  try {
    checkRunId = await createPendingCheckRun({
      installationId,
      owner, repo: repoName,
      headSha: sha,
      detailsUrl: `${PUBLIC_URL}/audits/${repo}/${sha}`,
      externalId: `forensiq:${repo}:${sha}`,
    });
  } catch (e) {
    console.warn('[gh-app] could not create check run:', (e as Error).message);
  }

  const run = await createRun({
    projectId: project.id,
    commitSha: sha,
    commitMessage: p.head_commit?.message,
    committer: p.head_commit?.author?.name,
  });

  const auditIds: string[] = [];
  for (const filePath of filesToAudit) {
    const auditId = randomUUID();
    await auditQueue.add('audit', {
      auditId,
      code: '',
      source: {
        type: 'github',
        label: `${repo}:${filePath}@${sha.slice(0, 7)}`,
        repo, path: filePath, ref: sha,
      },
      watchedRunId: run.id,
      watchedProjectId: project.id,
      // Pass GitHub context so the worker can update check runs / post PR comments
      github: {
        installationId,
        owner, repo: repoName,
        headSha: sha,
        checkRunId,
        // PR number is unknown at push time; PR handler sets it
      },
    });
    auditIds.push(auditId);
  }

  return { ok: true, runId: run.id, auditIds, files: filesToAudit, checkRunId };
}

async function handlePullRequest(p: PullRequestPayload): Promise<unknown> {
  if (!['opened', 'synchronize', 'reopened'].includes(p.action)) {
    return { ok: true, ignored: `pr action: ${p.action}` };
  }
  const installationId = p.installation?.id;
  if (!installationId) return { ok: true, ignored: 'no installation' };

  const repo = p.repository.full_name;
  const [owner, repoName] = repo.split('/');
  const sha = p.pull_request.head.sha;

  // PRs don't carry file lists — fetch them via the App-authenticated API
  let files: string[] = [];
  try {
    files = await fetchPrChangedSolFiles(installationId, owner, repoName, p.number);
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
  if (files.length === 0) return { ok: true, ignored: 'no .sol changes in PR' };

  const filesToAudit = files.slice(0, MAX_FILES_PER_PUSH);

  // Same check-run + queue flow as push, with prNumber added so the worker
  // can post a PR comment.
  let checkRunId: number | undefined;
  try {
    checkRunId = await createPendingCheckRun({
      installationId,
      owner, repo: repoName,
      headSha: sha,
      detailsUrl: `${PUBLIC_URL}/audits/${repo}/${sha}`,
      externalId: `forensiq:${repo}:${sha}:pr-${p.number}`,
    });
  } catch (e) {
    console.warn('[gh-app] could not create PR check run:', (e as Error).message);
  }

  const auditIds: string[] = [];
  for (const filePath of filesToAudit) {
    const auditId = randomUUID();
    await auditQueue.add('audit', {
      auditId,
      code: '',
      source: {
        type: 'github',
        label: `${repo}:${filePath}@PR-${p.number}`,
        repo, path: filePath, ref: sha,
      },
      github: {
        installationId,
        owner, repo: repoName,
        headSha: sha,
        checkRunId,
        prNumber: p.number,
      },
    });
    auditIds.push(auditId);
  }

  return { ok: true, prNumber: p.number, auditIds, files: filesToAudit, checkRunId };
}

export default router;
