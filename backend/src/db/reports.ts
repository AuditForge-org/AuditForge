/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Reports persistence — Postgres via pg.
 *
 * Schema (run /docker/init.sql to bootstrap):
 *
 *   CREATE TABLE reports (
 *     id          UUID PRIMARY KEY,
 *     created_at  TIMESTAMPTZ DEFAULT now(),
 *     score       INTEGER NOT NULL,
 *     grade       TEXT NOT NULL,
 *     source_type TEXT NOT NULL,
 *     source_label TEXT NOT NULL,
 *     payload     JSONB NOT NULL
 *   );
 *   CREATE INDEX reports_created_at_idx ON reports (created_at DESC);
 *   CREATE INDEX reports_score_idx ON reports (score);
 */

import { Pool } from 'pg';
import { AuditReport } from '../types/finding';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    'postgres://forensiq:forensiq@localhost:5432/forensiq',
  max: 10,
});

export async function saveReport(report: AuditReport): Promise<void> {
  await pool.query(
    `INSERT INTO reports (id, created_at, score, grade, source_type, source_label, payload, owner_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, owner_id = COALESCE(reports.owner_id, EXCLUDED.owner_id)`,
    [
      report.id,
      report.createdAt,
      report.score,
      report.grade,
      report.source.type,
      report.source.label,
      JSON.stringify(report),
      report.ownerId ?? null,
    ]
  );
}

export async function getReport(id: string): Promise<AuditReport | null> {
  // Return the payload JSON but always re-attach owner_id from the column
  // (the JSON copy may be stale if a future migration re-assigned ownership).
  const res = await pool.query(
    `SELECT payload, owner_id FROM reports WHERE id = $1`,
    [id]
  );
  if (res.rows.length === 0) return null;
  const payload = res.rows[0].payload as AuditReport;
  payload.ownerId = res.rows[0].owner_id ?? undefined;
  return payload;
}

export async function listReports(limit = 20): Promise<Array<Pick<AuditReport,
  'id' | 'createdAt' | 'score' | 'grade' | 'source'>>> {
  const res = await pool.query(
    `SELECT id, created_at, score, grade, source_type, source_label
     FROM reports
     ORDER BY created_at DESC
     LIMIT $1`,
    [limit]
  );
  return res.rows.map(r => ({
    id: r.id,
    createdAt: r.created_at.toISOString(),
    score: r.score,
    grade: r.grade,
    source: { type: r.source_type, label: r.source_label } as AuditReport['source'],
  }));
}

export async function shutdown(): Promise<void> {
  await pool.end();
}
