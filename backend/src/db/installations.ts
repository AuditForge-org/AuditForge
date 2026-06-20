/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — GitHub App installations.
 *
 * When a user installs the Forensiq GitHub App on their account or org,
 * GitHub fires an `installation.created` webhook. We record the
 * installation ID + the set of repositories it covers.
 *
 * On every push from that installation we look up the installation ID
 * to mint a fresh token. The installation can be deleted (uninstalled)
 * or have its repo selection changed at any time.
 *
 * Schema:
 *
 *   CREATE TABLE github_installations (
 *     installation_id BIGINT PRIMARY KEY,
 *     account_login   TEXT NOT NULL,
 *     account_type    TEXT NOT NULL,         -- 'User' | 'Organization'
 *     created_at      TIMESTAMPTZ DEFAULT now(),
 *     repo_selection  TEXT NOT NULL,         -- 'all' | 'selected'
 *     repos           TEXT[] DEFAULT '{}',   -- empty when selection = 'all'
 *     suspended       BOOLEAN DEFAULT false,
 *     owner_id        TEXT                   -- linked Forensiq user, if claimed
 *   );
 *
 *   CREATE INDEX gh_installs_account_idx ON github_installations (account_login);
 *   CREATE INDEX gh_installs_owner_idx   ON github_installations (owner_id);
 */

import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    'postgres://forensiq:forensiq@localhost:5432/forensiq',
});

export interface GithubInstallation {
  installationId: number;
  accountLogin: string;
  accountType: 'User' | 'Organization';
  createdAt: string;
  repoSelection: 'all' | 'selected';
  repos: string[];          // 'owner/repo' format
  suspended: boolean;
  ownerId?: string;
}

export async function upsertInstallation(inst: Omit<GithubInstallation, 'createdAt'>): Promise<void> {
  await pool.query(
    `INSERT INTO github_installations
       (installation_id, account_login, account_type, repo_selection, repos, suspended, owner_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (installation_id) DO UPDATE SET
       account_login = EXCLUDED.account_login,
       account_type = EXCLUDED.account_type,
       repo_selection = EXCLUDED.repo_selection,
       repos = EXCLUDED.repos,
       suspended = EXCLUDED.suspended,
       owner_id = COALESCE(EXCLUDED.owner_id, github_installations.owner_id)`,
    [
      inst.installationId, inst.accountLogin, inst.accountType,
      inst.repoSelection, inst.repos, inst.suspended, inst.ownerId,
    ]
  );
}

export async function getInstallation(installationId: number): Promise<GithubInstallation | null> {
  const res = await pool.query(
    `SELECT * FROM github_installations WHERE installation_id = $1`,
    [installationId]
  );
  return res.rows[0] ? rowToInstallation(res.rows[0]) : null;
}

/**
 * Find an installation that covers a given repository. Used when a push
 * arrives — we need the installation id to mint a token for that repo.
 */
export async function findInstallationForRepo(repo: string): Promise<GithubInstallation | null> {
  const res = await pool.query(
    `SELECT * FROM github_installations
     WHERE suspended = false
       AND (repo_selection = 'all' AND account_login = $1
            OR $2 = ANY(repos))
     LIMIT 1`,
    [repo.split('/')[0], repo]
  );
  return res.rows[0] ? rowToInstallation(res.rows[0]) : null;
}

export async function deleteInstallation(installationId: number): Promise<void> {
  await pool.query(`DELETE FROM github_installations WHERE installation_id = $1`, [installationId]);
}

export async function listInstallationsByOwner(ownerId: string): Promise<GithubInstallation[]> {
  const res = await pool.query(
    `SELECT * FROM github_installations WHERE owner_id = $1 ORDER BY created_at DESC`,
    [ownerId]
  );
  return res.rows.map(rowToInstallation);
}

/**
 * Link an installation to a Forensiq user account. Called from the OAuth
 * redirect handler after the user authorizes Forensiq and we know their
 * GitHub identity matches the installation account.
 */
export async function claimInstallation(installationId: number, ownerId: string): Promise<boolean> {
  const res = await pool.query(
    `UPDATE github_installations SET owner_id = $1
     WHERE installation_id = $2 AND owner_id IS NULL`,
    [ownerId, installationId]
  );
  return (res.rowCount ?? 0) > 0;
}

function rowToInstallation(r: Record<string, unknown>): GithubInstallation {
  return {
    installationId: Number(r.installation_id),
    accountLogin: r.account_login as string,
    accountType: r.account_type as 'User' | 'Organization',
    createdAt: (r.created_at as Date).toISOString(),
    repoSelection: r.repo_selection as 'all' | 'selected',
    repos: (r.repos as string[]) ?? [],
    suspended: r.suspended as boolean,
    ownerId: r.owner_id as string | undefined,
  };
}
