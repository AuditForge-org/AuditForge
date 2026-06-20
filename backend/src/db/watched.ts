/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Watched projects.
 *
 * A "watched project" is a repo (or specific path within a repo) that the
 * user has subscribed to monitor. Every push event from GitHub triggers
 * an audit run scoped to the changed Solidity files.
 *
 * Schema:
 *
 *   CREATE TABLE watched_projects (
 *     id             UUID PRIMARY KEY,
 *     created_at     TIMESTAMPTZ DEFAULT now(),
 *     owner_id       TEXT NOT NULL,           -- user id from auth layer
 *     repo           TEXT NOT NULL,           -- "owner/repo"
 *     path_filter    TEXT,                    -- optional path prefix like "contracts/"
 *     branch         TEXT DEFAULT 'main',
 *     webhook_secret TEXT NOT NULL,           -- per-project HMAC secret
 *     enabled        BOOLEAN DEFAULT true,
 *     notify_email   TEXT,
 *     notify_slack   TEXT,
 *     min_severity   TEXT DEFAULT 'medium',
 *     UNIQUE (repo, path_filter, branch)
 *   );
 *
 *   CREATE TABLE watched_runs (
 *     id             UUID PRIMARY KEY,
 *     project_id     UUID REFERENCES watched_projects(id) ON DELETE CASCADE,
 *     audit_id       UUID,                    -- → reports.id when complete
 *     created_at     TIMESTAMPTZ DEFAULT now(),
 *     commit_sha     TEXT NOT NULL,
 *     commit_message TEXT,
 *     committer      TEXT,
 *     status         TEXT NOT NULL,           -- 'queued'|'running'|'complete'|'failed'
 *     score_delta    INTEGER,                 -- vs previous run on this project
 *     findings_delta INTEGER
 *   );
 */

import { Pool } from 'pg';
import { randomBytes, randomUUID } from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    'postgres://forensiq:forensiq@localhost:5432/forensiq',
});

export interface WatchedProject {
  id: string;
  createdAt: string;
  ownerId: string;
  repo: string;
  pathFilter?: string;
  branch: string;
  webhookSecret: string;
  enabled: boolean;
  notifyEmail?: string;
  notifySlack?: string;
  minSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface WatchedRun {
  id: string;
  projectId: string;
  auditId?: string;
  createdAt: string;
  commitSha: string;
  commitMessage?: string;
  committer?: string;
  status: 'queued' | 'running' | 'complete' | 'failed';
  scoreDelta?: number;
  findingsDelta?: number;
}

/**
 * Generate a cryptographically strong webhook secret. The user adds this
 * as the secret on their GitHub webhook; we verify every incoming
 * payload against it.
 */
function generateWebhookSecret(): string {
  return randomBytes(32).toString('hex');
}

export async function createWatchedProject(opts: {
  ownerId: string;
  repo: string;
  pathFilter?: string;
  branch?: string;
  notifyEmail?: string;
  notifySlack?: string;
  minSeverity?: WatchedProject['minSeverity'];
}): Promise<WatchedProject> {
  const id = randomUUID();
  const secret = generateWebhookSecret();
  const branch = opts.branch || 'main';
  const minSeverity = opts.minSeverity || 'medium';

  const res = await pool.query(
    `INSERT INTO watched_projects
       (id, owner_id, repo, path_filter, branch, webhook_secret, notify_email, notify_slack, min_severity)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING *`,
    [id, opts.ownerId, opts.repo, opts.pathFilter, branch, secret,
     opts.notifyEmail, opts.notifySlack, minSeverity]
  );

  return rowToProject(res.rows[0]);
}

export async function getWatchedProject(id: string): Promise<WatchedProject | null> {
  const res = await pool.query(`SELECT * FROM watched_projects WHERE id = $1`, [id]);
  return res.rows[0] ? rowToProject(res.rows[0]) : null;
}

/**
 * Find watched projects matching the incoming webhook. A push to
 * "alice/contracts" on branch "main" might match multiple projects if
 * different users have subscribed to it with different path filters.
 */
export async function findMatchingProjects(repo: string, branch: string): Promise<WatchedProject[]> {
  const res = await pool.query(
    `SELECT * FROM watched_projects
     WHERE repo = $1 AND branch = $2 AND enabled = true`,
    [repo, branch]
  );
  return res.rows.map(rowToProject);
}

export async function listProjectsByOwner(ownerId: string): Promise<WatchedProject[]> {
  const res = await pool.query(
    `SELECT * FROM watched_projects WHERE owner_id = $1 ORDER BY created_at DESC`,
    [ownerId]
  );
  return res.rows.map(rowToProject);
}

export async function deleteWatchedProject(id: string, ownerId: string): Promise<boolean> {
  const res = await pool.query(
    `DELETE FROM watched_projects WHERE id = $1 AND owner_id = $2`,
    [id, ownerId]
  );
  return (res.rowCount || 0) > 0;
}

// ─── Runs ────────────────────────────────────────────────────────────

export async function createRun(opts: {
  projectId: string;
  commitSha: string;
  commitMessage?: string;
  committer?: string;
}): Promise<WatchedRun> {
  const id = randomUUID();
  const res = await pool.query(
    `INSERT INTO watched_runs
       (id, project_id, commit_sha, commit_message, committer, status)
     VALUES ($1, $2, $3, $4, $5, 'queued')
     RETURNING *`,
    [id, opts.projectId, opts.commitSha, opts.commitMessage, opts.committer]
  );
  return rowToRun(res.rows[0]);
}

export async function updateRunStatus(
  id: string,
  status: WatchedRun['status'],
  patch: { auditId?: string; scoreDelta?: number; findingsDelta?: number } = {}
): Promise<void> {
  await pool.query(
    `UPDATE watched_runs
     SET status = $2, audit_id = COALESCE($3, audit_id),
         score_delta = COALESCE($4, score_delta),
         findings_delta = COALESCE($5, findings_delta)
     WHERE id = $1`,
    [id, status, patch.auditId, patch.scoreDelta, patch.findingsDelta]
  );
}

/**
 * Get the most recent completed run for a project — used to compute
 * the score delta on a new run.
 */
export async function getLatestCompletedRun(projectId: string): Promise<WatchedRun | null> {
  const res = await pool.query(
    `SELECT * FROM watched_runs
     WHERE project_id = $1 AND status = 'complete'
     ORDER BY created_at DESC LIMIT 1`,
    [projectId]
  );
  return res.rows[0] ? rowToRun(res.rows[0]) : null;
}

export async function listRunsForProject(projectId: string, limit = 20): Promise<WatchedRun[]> {
  const res = await pool.query(
    `SELECT * FROM watched_runs WHERE project_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [projectId, limit]
  );
  return res.rows.map(rowToRun);
}

// ─── Row mappers ─────────────────────────────────────────────────────

function rowToProject(r: Record<string, unknown>): WatchedProject {
  return {
    id: r.id as string,
    createdAt: (r.created_at as Date).toISOString(),
    ownerId: r.owner_id as string,
    repo: r.repo as string,
    pathFilter: r.path_filter as string | undefined,
    branch: r.branch as string,
    webhookSecret: r.webhook_secret as string,
    enabled: r.enabled as boolean,
    notifyEmail: r.notify_email as string | undefined,
    notifySlack: r.notify_slack as string | undefined,
    minSeverity: r.min_severity as WatchedProject['minSeverity'],
  };
}

function rowToRun(r: Record<string, unknown>): WatchedRun {
  return {
    id: r.id as string,
    projectId: r.project_id as string,
    auditId: r.audit_id as string | undefined,
    createdAt: (r.created_at as Date).toISOString(),
    commitSha: r.commit_sha as string,
    commitMessage: r.commit_message as string | undefined,
    committer: r.committer as string | undefined,
    status: r.status as WatchedRun['status'],
    scoreDelta: r.score_delta as number | undefined,
    findingsDelta: r.findings_delta as number | undefined,
  };
}
