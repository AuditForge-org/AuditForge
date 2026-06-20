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
 *     github_user_id  BIGINT UNIQUE NOT NULL,
 *     github_username TEXT NOT NULL,
 *     email           TEXT,
 *     avatar_url      TEXT,
 *     plan            TEXT NOT NULL DEFAULT 'free'
 *   );
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
  githubUserId: number;
  githubUsername: string;
  email?: string;
  avatarUrl?: string;
  plan: 'free' | 'pro' | 'team';
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
    githubUserId: Number(r.github_user_id),
    githubUsername: r.github_username as string,
    email: r.email as string | undefined,
    avatarUrl: r.avatar_url as string | undefined,
    plan: r.plan as User['plan'],
  };
}
