/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Public registry.
 *
 * Reports are private by default. Owners can opt-in to publish a report
 * to the public registry, which surfaces it in:
 *   - The leaderboard (sorted by score with severity filters)
 *   - Per-contract / per-address lookup
 *   - The dApp-stack browse view (group by chain)
 *   - Search by name, address, source repo
 *
 * Publishing is irreversible in terms of indexing — once published, the
 * report becomes part of the historical record. Owners can mark it
 * "superseded" by a newer audit but cannot remove the original (this is
 * intentional: an audit firm couldn't retract a bad report either).
 *
 * Schema:
 *
 *   CREATE TABLE registry_entries (
 *     id              UUID PRIMARY KEY,
 *     report_id       UUID NOT NULL REFERENCES reports(id),
 *     published_at    TIMESTAMPTZ DEFAULT now(),
 *     published_by    TEXT NOT NULL,
 *     contract_name   TEXT,
 *     chain           TEXT,
 *     address         TEXT,
 *     repo            TEXT,
 *     tags            TEXT[] DEFAULT '{}',
 *     score           INTEGER NOT NULL,
 *     grade           TEXT NOT NULL,
 *     findings_count  INTEGER NOT NULL,
 *     critical_count  INTEGER DEFAULT 0,
 *     high_count      INTEGER DEFAULT 0,
 *     superseded_by   UUID REFERENCES registry_entries(id),
 *     verified_source BOOLEAN DEFAULT false,
 *     UNIQUE (chain, address)  -- one current entry per on-chain contract
 *   );
 *
 *   CREATE INDEX registry_score_idx ON registry_entries (score DESC);
 *   CREATE INDEX registry_chain_idx ON registry_entries (chain);
 *   CREATE INDEX registry_published_idx ON registry_entries (published_at DESC);
 *   CREATE INDEX registry_tags_idx ON registry_entries USING gin (tags);
 *
 *   -- Full-text search
 *   CREATE INDEX registry_search_idx ON registry_entries
 *     USING gin (to_tsvector('english',
 *       coalesce(contract_name,'') || ' ' ||
 *       coalesce(repo,'') || ' ' ||
 *       coalesce(address,'')));
 */

import { Pool } from 'pg';
import { randomUUID } from 'crypto';
import { AuditReport, Severity } from '../types/finding';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ||
    'postgres://forensiq:forensiq@localhost:5432/forensiq',
});

export interface RegistryEntry {
  id: string;
  reportId: string;
  publishedAt: string;
  publishedBy: string;
  contractName?: string;
  chain?: string;
  address?: string;
  repo?: string;
  tags: string[];
  score: number;
  grade: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  supersededBy?: string;
  verifiedSource: boolean;
}

function countSeverity(report: AuditReport, sev: Severity): number {
  return report.consensusFindings.filter(f => f.severity === sev).length;
}

/**
 * Publish a report to the public registry.
 *
 * If a previous entry exists for the same (chain, address) tuple, the
 * old entry is marked superseded by the new one. This lets the
 * leaderboard show the *current* score for each contract while
 * preserving history.
 */
export async function publishReport(
  reportId: string,
  publishedBy: string,
  report: AuditReport,
  opts: { tags?: string[]; verifiedSource?: boolean } = {}
): Promise<RegistryEntry> {
  const id = randomUUID();
  const chain = report.source.chain;
  const address = report.source.address?.toLowerCase();
  const repo = report.source.repo;

  // Best-effort contract name from source label
  const contractName = extractContractName(report);

  const findingsCount = report.consensusFindings.length;
  const criticalCount = countSeverity(report, 'critical');
  const highCount = countSeverity(report, 'high');

  // Mark prior entry as superseded if (chain, address) collision
  if (chain && address) {
    await pool.query(
      `UPDATE registry_entries SET superseded_by = $1
       WHERE chain = $2 AND address = $3 AND superseded_by IS NULL`,
      [id, chain, address]
    );
  }

  const res = await pool.query(
    `INSERT INTO registry_entries
       (id, report_id, published_by, contract_name, chain, address, repo, tags,
        score, grade, findings_count, critical_count, high_count, verified_source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING *`,
    [id, reportId, publishedBy, contractName, chain, address, repo,
     opts.tags || [], report.score, report.grade, findingsCount,
     criticalCount, highCount, opts.verifiedSource ?? false]
  );

  return rowToEntry(res.rows[0]);
}

function extractContractName(report: AuditReport): string | undefined {
  // Try to find the last `contract X` in the source
  const m = report.contract.code.match(/contract\s+(\w+)\s*(?:is\s+[^{]*)?\{/g);
  if (m && m.length > 0) {
    const last = m[m.length - 1];
    const nameMatch = last.match(/contract\s+(\w+)/);
    return nameMatch?.[1];
  }
  return undefined;
}

// ─── Read endpoints ──────────────────────────────────────────────────

export interface LeaderboardFilters {
  chain?: string;
  minScore?: number;
  maxScore?: number;
  tag?: string;
  search?: string;
  /** 'current' = only non-superseded entries (default); 'all' = include history */
  scope?: 'current' | 'all';
  sort?: 'score_desc' | 'score_asc' | 'published_desc' | 'critical_desc';
  limit?: number;
  offset?: number;
}

export async function getLeaderboard(filters: LeaderboardFilters = {}): Promise<{
  entries: RegistryEntry[];
  total: number;
}> {
  const scope = filters.scope ?? 'current';
  const limit = Math.min(filters.limit ?? 50, 200);
  const offset = filters.offset ?? 0;

  const where: string[] = [];
  const params: unknown[] = [];

  if (scope === 'current') where.push('superseded_by IS NULL');
  if (filters.chain) { params.push(filters.chain); where.push(`chain = $${params.length}`); }
  if (filters.minScore != null) { params.push(filters.minScore); where.push(`score >= $${params.length}`); }
  if (filters.maxScore != null) { params.push(filters.maxScore); where.push(`score <= $${params.length}`); }
  if (filters.tag) { params.push(filters.tag); where.push(`$${params.length} = ANY(tags)`); }
  if (filters.search) {
    params.push(filters.search);
    where.push(`to_tsvector('english',
      coalesce(contract_name,'') || ' ' ||
      coalesce(repo,'') || ' ' ||
      coalesce(address,'')) @@ plainto_tsquery('english', $${params.length})`);
  }

  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const sortMap: Record<string, string> = {
    score_desc: 'score DESC, published_at DESC',
    score_asc: 'score ASC, published_at DESC',
    published_desc: 'published_at DESC',
    critical_desc: 'critical_count DESC, high_count DESC, score ASC',
  };
  const orderBy = sortMap[filters.sort ?? 'score_desc'];

  // Total count
  const countRes = await pool.query(
    `SELECT COUNT(*)::int AS n FROM registry_entries ${whereClause}`, params
  );
  const total = countRes.rows[0].n as number;

  params.push(limit, offset);
  const res = await pool.query(
    `SELECT * FROM registry_entries
     ${whereClause}
     ORDER BY ${orderBy}
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );

  return { entries: res.rows.map(rowToEntry), total };
}

export async function getEntryByAddress(chain: string, address: string): Promise<RegistryEntry | null> {
  const res = await pool.query(
    `SELECT * FROM registry_entries
     WHERE chain = $1 AND address = $2 AND superseded_by IS NULL
     LIMIT 1`,
    [chain, address.toLowerCase()]
  );
  return res.rows[0] ? rowToEntry(res.rows[0]) : null;
}

export async function getEntryHistory(chain: string, address: string): Promise<RegistryEntry[]> {
  const res = await pool.query(
    `SELECT * FROM registry_entries
     WHERE chain = $1 AND address = $2
     ORDER BY published_at DESC`,
    [chain, address.toLowerCase()]
  );
  return res.rows.map(rowToEntry);
}

export async function getChainStats(): Promise<Array<{
  chain: string;
  entries: number;
  averageScore: number;
  criticalCount: number;
}>> {
  const res = await pool.query(`
    SELECT chain,
           COUNT(*)::int AS entries,
           AVG(score)::int AS average_score,
           SUM(critical_count)::int AS critical_count
    FROM registry_entries
    WHERE superseded_by IS NULL AND chain IS NOT NULL
    GROUP BY chain
    ORDER BY entries DESC
  `);
  return res.rows.map((r: Record<string, unknown>) => ({
    chain: r.chain as string,
    entries: r.entries as number,
    averageScore: r.average_score as number,
    criticalCount: r.critical_count as number,
  }));
}

function rowToEntry(r: Record<string, unknown>): RegistryEntry {
  return {
    id: r.id as string,
    reportId: r.report_id as string,
    publishedAt: (r.published_at as Date).toISOString(),
    publishedBy: r.published_by as string,
    contractName: r.contract_name as string | undefined,
    chain: r.chain as string | undefined,
    address: r.address as string | undefined,
    repo: r.repo as string | undefined,
    tags: (r.tags as string[]) || [],
    score: r.score as number,
    grade: r.grade as string,
    findingsCount: r.findings_count as number,
    criticalCount: r.critical_count as number,
    highCount: r.high_count as number,
    supersededBy: r.superseded_by as string | undefined,
    verifiedSource: r.verified_source as boolean,
  };
}
