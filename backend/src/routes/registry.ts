/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Registry HTTP routes.
 *
 *   POST   /api/registry/publish/:reportId    publish a report (auth)
 *   GET    /api/registry                      leaderboard with filters (public)
 *   GET    /api/registry/chains               aggregate stats per chain (public)
 *   GET    /api/registry/contract/:chain/:addr  full history for a contract (public)
 *   GET    /api/registry/entry/:id            single entry (public)
 *
 * Publish requires the requesting user to own the underlying report.
 * Reads are public.
 */

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import {
  publishReport,
  getLeaderboard,
  getEntryByAddress,
  getEntryHistory,
  getChainStats,
} from '../registry/store';
import { getReport } from '../db/reports';
import { requireAuth } from '../auth';

const router = Router();

// ─── Public read endpoints ───────────────────────────────────────────

const LeaderboardSchema = z.object({
  chain: z.string().optional(),
  minScore: z.coerce.number().min(0).max(100).optional(),
  maxScore: z.coerce.number().min(0).max(100).optional(),
  tag: z.string().optional(),
  search: z.string().max(120).optional(),
  scope: z.enum(['current', 'all']).optional(),
  sort: z.enum(['score_desc', 'score_asc', 'published_desc', 'critical_desc']).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

router.get('/', async (req: Request, res: Response) => {
  const parsed = LeaderboardSchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const result = await getLeaderboard(parsed.data);
  res.json(result);
});

router.get('/chains', async (_req: Request, res: Response) => {
  const stats = await getChainStats();
  res.json({ chains: stats });
});

router.get('/contract/:chain/:address', async (req: Request, res: Response) => {
  const address = req.params.address.toLowerCase();
  if (!/^0x[a-f0-9]{40}$/.test(address)) {
    return res.status(400).json({ error: 'Invalid address' });
  }
  const current = await getEntryByAddress(req.params.chain, address);
  const history = await getEntryHistory(req.params.chain, address);
  res.json({ current, history });
});

// ─── Publish (auth) ──────────────────────────────────────────────────

const PublishSchema = z.object({
  tags: z.array(z.string().min(1).max(30)).max(10).optional(),
  verifiedSource: z.boolean().optional(),
});

router.post('/publish/:reportId', requireAuth, async (req: Request, res: Response) => {
  const parsed = PublishSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });

  const report = await getReport(req.params.reportId);
  if (!report) return res.status(404).json({ error: 'Report not found' });

  // Ownership check: only the user who created the report may publish it.
  // The `owner_id` column on reports is populated when audits are submitted
  // by an authenticated user. Reports submitted anonymously have null owner
  // and cannot be published.
  if (!report.ownerId || report.ownerId !== req.userId!) {
    return res.status(403).json({ error: 'You may only publish reports you created' });
  }

  const entry = await publishReport(
    req.params.reportId,
    req.userId!,
    report,
    parsed.data
  );

  res.status(201).json({ entry });
});

export default router;
