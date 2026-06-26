/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Users.
 *
 * Users are created on first OAuth login. The primary identity is the
 * GitHub user id (stable, doesn't change when username changes). We also
 * keep the username for display purposes and update it on each login.
 *
 * Schema:
 *
 *   CREATE TABLE users (
 *     id              UUID PRIMARY KEY,
 *     created_at      TIMESTAMPTZ DEFAULT now(),
 *     last_login_at   TIMESTAMPTZ DEFAULT now(),
 *     github_user_id  BIGINT UNIQUE,          -- nullable: Google-only accounts have none
 *     github_username TEXT,
 *     google_user_id  TEXT UNIQUE,            -- OIDC `sub`; nullable for GitHub-only
 *     display_name    TEXT,                   -- provider-agnostic display label
 *     email           TEXT,
 *     avatar_url      TEXT,
 *     plan            TEXT NOT NULL DEFAULT 'free'
 *   );
 *
 * An account may carry both ids once linked by verified email. Either id is
 * sufficient to identify a user; at least one is always present.
 */

import { Pool } from 'pg';
import { randomUUID } from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    'postgres://forensiq:forensiq@localhost:5432/forensiq',
});

export interface User {
  id: string;
  createdAt: string;
  lastLoginAt: string;
  /** Present for GitHub-provisioned accounts. */
  githubUserId?: number;
  githubUsername?: string;
  /** Present for Google-provisioned accounts (the OIDC `sub`, a string). */
  googleUserId?: string;
  /** Provider-agnostic display name (Google full name, etc.). */
  displayName?: string;
  email?: string;
  avatarUrl?: string;
  plan: 'free' | 'pro' | 'team';
}

/** Provider-agnostic label for the signed-in user (display only, not security). */
export function displayNameOf(u: User): string {
  return u.displayName || u.githubUsername ||
    (u.email ? u.email.split('@')[0] : '') || 'account';
}

/**
 * Upsert by GitHub user id. Username is updated on every login since users
 * can rename themselves on GitHub.
 */
export async function upsertUserFromGithub(opts: {
  githubUserId: number;
  githubUsername: string;
  email?: string;
  avatarUrl?: string;
}): Promise<User> {
  const id = randomUUID();
  const res = await pool.query(
    `INSERT INTO users (id, github_user_id, github_username, email, avatar_url)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (github_user_id) DO UPDATE SET
       github_username = EXCLUDED.github_username,
       email = COALESCE(EXCLUDED.email, users.email),
       avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
       last_login_at = now()
     RETURNING *`,
    [id, opts.githubUserId, opts.githubUsername, opts.email, opts.avatarUrl]
  );
  return rowToUser(res.rows[0]);
}

/**
 * Upsert by Google OIDC `sub`. If no Google account exists yet but a prior
 * account shares the same *verified* email (e.g. the user signed in with
 * GitHub before), we link Google to that existing account rather than
 * creating a duplicate. Linking is gated on `emailVerified` so an attacker
 * can't claim someone else's account by asserting their email.
 */
export async function upsertUserFromGoogle(opts: {
  googleUserId: string;
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
}): Promise<User> {
  // 1) Existing Google account → update + return.
  const byG = await pool.query(`SELECT * FROM users WHERE google_user_id = $1`, [opts.googleUserId]);
  if (byG.rows[0]) {
    const upd = await pool.query(
      `UPDATE users SET
         email = COALESCE($2, email),
         display_name = COALESCE($3, display_name),
         avatar_url = COALESCE($4, avatar_url),
         last_login_at = now()
       WHERE google_user_id = $1 RETURNING *`,
      [opts.googleUserId, opts.email, opts.displayName, opts.avatarUrl]
    );
    return rowToUser(upd.rows[0]);
  }

  // 2) Link to an existing (e.g. GitHub) account by verified email.
  if (opts.email && opts.emailVerified) {
    const byE = await pool.query(
      `SELECT * FROM users WHERE lower(email) = lower($1) AND google_user_id IS NULL LIMIT 1`,
      [opts.email]
    );
    if (byE.rows[0]) {
      const upd = await pool.query(
        `UPDATE users SET
           google_user_id = $2,
           display_name = COALESCE(display_name, $3),
           avatar_url = COALESCE(avatar_url, $4),
           last_login_at = now()
         WHERE id = $1 RETURNING *`,
        [byE.rows[0].id, opts.googleUserId, opts.displayName, opts.avatarUrl]
      );
      return rowToUser(upd.rows[0]);
    }
  }

  // 3) New Google-only account.
  const id = randomUUID();
  const ins = await pool.query(
    `INSERT INTO users (id, google_user_id, display_name, email, avatar_url)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [id, opts.googleUserId, opts.displayName, opts.email, opts.avatarUrl]
  );
  return rowToUser(ins.rows[0]);
}

export async function getUserById(id: string): Promise<User | null> {
  const res = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
  return res.rows[0] ? rowToUser(res.rows[0]) : null;
}

export async function getUserByGithubId(ghId: number): Promise<User | null> {
  const res = await pool.query(`SELECT * FROM users WHERE github_user_id = $1`, [ghId]);
  return res.rows[0] ? rowToUser(res.rows[0]) : null;
}

function rowToUser(r: Record<string, unknown>): User {
  return {
    id: r.id as string,
    createdAt: (r.created_at as Date).toISOString(),
    lastLoginAt: (r.last_login_at as Date).toISOString(),
    githubUserId: r.github_user_id != null ? Number(r.github_user_id) : undefined,
    githubUsername: (r.github_username as string) || undefined,
    googleUserId: (r.google_user_id as string) || undefined,
    displayName: (r.display_name as string) || undefined,
    email: r.email as string | undefined,
    avatarUrl: r.avatar_url as string | undefined,
    plan: r.plan as User['plan'],
  };
}
