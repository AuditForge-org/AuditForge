/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Watch project management routes.
 *
 *   POST   /api/watch                 create a watched project
 *   GET    /api/watch                 list user's watched projects
 *   GET    /api/watch/:id             get one (with webhook setup instructions)
 *   DELETE /api/watch/:id             unwatch
 *   GET    /api/watch/:id/runs        list recent runs
 *
 * Auth: all routes require a logged-in user (req.user populated by
 * the `optionalAuth` middleware in server.ts + `requireAuth` here).
 */

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import {
  createWatchedProject,
  listProjectsByOwner,
  getWatchedProject,
  deleteWatchedProject,
  listRunsForProject,
} from '../db/watched';
import { requireAuth } from '../auth';

const router = Router();
router.use(requireAuth);

const CreateSchema = z.object({
  repo: z.string().regex(/^[\w.-]+\/[\w.-]+$/, 'Must be "owner/repo"'),
  pathFilter: z.string().optional(),
  branch: z.string().default('main'),
  notifyEmail: z.string().email().optional(),
  notifySlack: z.string().url().optional(),
  minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
});

router.post('/', async (req: Request, res: Response) => {
  const parsed = CreateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });

  const project = await createWatchedProject({
    ownerId: req.userId!,
    ...parsed.data,
  });

  // Return setup instructions
  const baseUrl = process.env.PUBLIC_URL || `http://localhost:${process.env.PORT || 3000}`;
  res.status(201).json({
    project,
    setup: {
      webhookUrl: `${baseUrl}/api/webhooks/github`,
      secret: project.webhookSecret,
      contentType: 'application/json',
      events: ['push'],
      instructions: `1. Go to https://github.com/${project.repo}/settings/hooks/new
2. Payload URL: ${baseUrl}/api/webhooks/github
3. Content type: application/json
4. Secret: ${project.webhookSecret}
5. Events: Just the push event
6. Active: ✓`,
    },
  });
});

router.get('/', async (req: Request, res: Response) => {
  const projects = await listProjectsByOwner(req.userId!);
  // Redact secrets from list view
  res.json({
    projects: projects.map(({ webhookSecret, ...rest }) => rest),
  });
});

router.get('/:id', async (req: Request, res: Response) => {
  const project = await getWatchedProject(req.params.id);
  if (!project || project.ownerId !== req.userId!) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({ project });
});

router.delete('/:id', async (req: Request, res: Response) => {
  const ok = await deleteWatchedProject(
    req.params.id,
    req.userId!
  );
  if (!ok) return res.status(404).json({ error: 'Not found' });
  res.status(204).end();
});

router.get('/:id/runs', async (req: Request, res: Response) => {
  const project = await getWatchedProject(req.params.id);
  if (!project || project.ownerId !== req.userId!) {
    return res.status(404).json({ error: 'Not found' });
  }
  const runs = await listRunsForProject(req.params.id, 50);
  res.json({ runs });
});

export default router;
