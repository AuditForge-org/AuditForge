/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — API Server
 *
 * Endpoints:
 *   POST   /api/audits             submit a new audit (returns jobId)
 *   GET    /api/audits/:id         fetch report (poll or check status)
 *   GET    /api/audits/:id/pdf     download report as PDF
 *   GET    /api/audits/:id/share   shareable view link
 *   POST   /api/source/etherscan   fetch verified source for an address
 *   POST   /api/source/github      fetch + flatten source from a repo
 *   GET    /api/health             liveness probe
 *
 * Body limit is intentionally generous (4MB) — flattened contracts can be
 * sizable. Production deployments should add request signing / API keys at
 * an upstream gateway.
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { Queue, QueueEvents } from 'bullmq';
import IORedis from 'ioredis';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import { fetchEtherscanSource } from './source/etherscan';
import { fetchGithubSource } from './source/github';
import { getReport, listReports } from './db/reports';
import { renderBadgeSvg, notFoundBadgeSvg, renderOgShell, renderOgPng, renderRegistryPage } from './share/og';
import { isReportPublished, getLeaderboard } from './registry/store';
import { buildPdf } from './reports/pdf';
import watchRoutes from './routes/watch';
import registryRoutes from './routes/registry';
import githubWebhook from './webhooks/github';
import githubAppWebhook from './github/webhook';
import authRoutes, { optionalAuth } from './auth';
import { log, withContext, setContext } from './observability/log';
import { httpMetricsMiddleware, renderMetrics, queueJobs } from './observability/metrics';
import { randomBytes } from 'crypto';

const PORT = parseInt(process.env.PORT || '3000', 10);
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

const connection = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });
const auditQueue = new Queue('audits', { connection });
const queueEvents = new QueueEvents('audits', { connection });

const app = express();
// Behind nginx — trust the first proxy so req.ip / X-Forwarded-For reflect the
// real client, making per-IP rate limiting correct (not bucketed under 127.0.0.1).
app.set('trust proxy', 1);

// ─── Observability middleware (must come first) ─────────────────────
// Request id: honor inbound header, else generate. Stable across logs + responses.
app.use((req, res, next) => {
  const incoming = req.header('x-request-id');
  const reqId = incoming || randomBytes(8).toString('hex');
  res.setHeader('X-Request-Id', reqId);
  withContext({ requestId: reqId }, () => {
    log.debug('request.start', { method: req.method, path: req.path });
    res.on('finish', () => {
      log.info('request.end', {
        method: req.method, path: req.path,
        status: res.statusCode,
      });
    });
    next();
  });
});
app.use(httpMetricsMiddleware);

// CORS: when the frontend is on a different origin, we must allow credentials
// (cookies) and explicitly echo the origin (wildcard is disallowed with credentials).
const FRONTEND_ORIGIN = process.env.FRONTEND_URL || process.env.PUBLIC_URL || true;
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));

// Webhook endpoints need RAW body for HMAC verification.
// Mount raw parser BEFORE json parser for these paths.
app.use('/api/webhooks/github',
  express.raw({ type: 'application/json', limit: '4mb' }),
  githubWebhook,
);
// GitHub App webhook (different from per-project legacy webhook above)
app.use('/api/gh',
  express.raw({ type: 'application/json', limit: '4mb' }),
  githubAppWebhook,
);

app.use(express.json({ limit: '4mb' }));

// Auth — every JSON route gets req.user populated (if logged in).
// Also propagate userId into log context so all downstream logs carry it.
app.use(async (req, res, next) => {
  await optionalAuth(req, res, () => {
    if (req.userId) setContext({ userId: req.userId });
    next();
  });
});

// Prometheus scrape endpoint (open within cluster; gate at ingress for production)
app.get('/metrics', (_req, res) => {
  res.type('text/plain; version=0.0.4').send(renderMetrics());
});

app.use('/api/auth', authRoutes);
app.use('/api/watch', watchRoutes);
app.use('/api/registry', registryRoutes);

// ─── Validation schemas ──────────────────────────────────────────────────

// Anonymous paste size ceiling (chars). Signed-in users get the full 2MB schema max.
const ANON_PASTE_MAX_BYTES = 512_000;

const SubmitAuditSchema = z.object({
  source: z.discriminatedUnion('type', [
    z.object({
      type: z.literal('paste'),
      code: z.string().min(20).max(2_000_000),
      filename: z.string().optional(),
    }),
    z.object({
      type: z.literal('address'),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
      chain: z.enum(['ethereum', 'ethw', 'bsc', 'polygon', 'arbitrum', 'optimism', 'base']),
    }),
    z.object({
      type: z.literal('github'),
      repo: z.string().min(3),
      path: z.string().optional(),
      ref: z.string().optional(),
    }),
  ]),
  tools: z.array(z.enum(['slither', 'mythril', 'aderyn', 'semgrep', 'solhint', 'echidna'])).optional(),
  solcVersion: z.string().optional(),
  /** Opt-in property-based fuzzing — adds several minutes to scan duration */
  enableFuzzing: z.boolean().optional(),
  /**
   * Publish the finished report to the public registry. Defaults to true, but
   * only ever takes effect for signed-in users (anonymous audits are never
   * auto-published). Set false to keep a signed-in audit private.
   */
  publish: z.boolean().optional(),
});

// ─── Middleware ──────────────────────────────────────────────────────────

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Redis-backed rate limiter — see middleware/ratelimit.ts for design
import { RATE_LIMITS } from './middleware/ratelimit';

// ─── Share surfaces — registered BEFORE the global limiter so README badge
//     renders and social crawlers are never throttled ──────────────────────

// Resolve a report by id, treating a malformed/unknown id as "not found"
// rather than letting a Postgres uuid error bubble to a 500 — these routes are
// hit by arbitrary crawlers and must always render something graceful.
async function safeGetReport(id: string) {
  try { return await getReport(id); } catch { return null; }
}

/** Embeddable SVG score badge (shields-style). e.g. /badge/<id>.svg */
app.get('/badge/:id', asyncHandler(async (req, res) => {
  const id = req.params.id.replace(/\.svg$/i, '');
  const report = await safeGetReport(id);
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=600, s-maxage=600');
  res.send(report ? renderBadgeSvg(report) : notFoundBadgeSvg());
}));

/** Server-rendered, crawlable report page. Indexed only when published. */
app.get('/r/:id', asyncHandler(async (req, res) => {
  const report = await safeGetReport(req.params.id);
  const origin = process.env.PUBLIC_URL || `https://${req.headers.host || 'auditforge.org'}`;
  const published = report ? await isReportPublished(req.params.id).catch(() => false) : false;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.send(renderOgShell(report, req.params.id, origin, published));
}));

/** Server-rendered, crawlable registry list. Interactive view stays at /#/registry. */
app.get('/registry', asyncHandler(async (req, res) => {
  const origin = process.env.PUBLIC_URL || `https://${req.headers.host || 'auditforge.org'}`;
  let entries: Awaited<ReturnType<typeof getLeaderboard>>['entries'] = [];
  let total = 0;
  try {
    const board = await getLeaderboard({ sort: 'score_desc', limit: 100 });
    entries = board.entries;
    total = board.total;
  } catch (e) {
    log.warn('registry page leaderboard failed', { err: String(e) });
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=120');
  res.send(renderRegistryPage(entries, total, origin));
}));

/** Per-report OG card PNG (score baked in). e.g. /og/<id>.png */
app.get('/og/:id', asyncHandler(async (req, res) => {
  const id = req.params.id.replace(/\.png$/i, '');
  const report = await safeGetReport(id);
  if (!report) return res.redirect(302, '/og-cover.png');
  try {
    const png = renderOgPng(report);
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=86400');
    return res.send(png);
  } catch (e) {
    console.error('[og png] render failed', e);
    return res.redirect(302, '/og-cover.png');
  }
}));

// Global API limit (post-auth so authenticated users get their own bucket)
app.use(RATE_LIMITS.api);

// ─── Routes ──────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/**
 * GET /api/config — public client config. Lets the frontend decide whether to
 * show "Sign in" and whether to render a Turnstile widget, without hardcoding.
 */
app.get('/api/config', (_req, res) => {
  res.json({
    authEnabled: !!(process.env.GITHUB_OAUTH_CLIENT_ID && process.env.GITHUB_OAUTH_CLIENT_SECRET && process.env.SESSION_SECRET),
    googleAuthEnabled: !!((process.env.GOOGLE_OAUTH_CLIENT_ID || process.env.GOOGLE_CLIENT_ID) && (process.env.GOOGLE_OAUTH_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET) && process.env.SESSION_SECRET),
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

/**
 * Cloudflare Turnstile verification. Dormant until TURNSTILE_SECRET_KEY is set,
 * so the live site is unaffected until you configure it. Fails open on a
 * verifier outage (same rationale as the rate limiter).
 */
async function verifyTurnstile(req: Request, res: Response, next: NextFunction) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return next(); // not configured → skip
  const token = (req.body && (req.body as { turnstileToken?: string }).turnstileToken) || '';
  if (!token) return res.status(403).json({ error: 'Captcha required. Please complete the verification and retry.' });
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: String(token), remoteip: req.ip || '' }),
      signal: AbortSignal.timeout(8_000),
    });
    const data = await r.json() as { success?: boolean };
    if (!data.success) return res.status(403).json({ error: 'Captcha verification failed. Please retry.' });
    next();
  } catch {
    next(); // verifier unreachable → don't block legitimate users
  }
}

/**
 * POST /api/audits
 * Accepts source by paste / address / github, resolves to flattened code,
 * enqueues a job, returns the job id.
 */
app.post('/api/audits', RATE_LIMITS.auditDaily, RATE_LIMITS.auditSubmit, verifyTurnstile, asyncHandler(async (req, res) => {
  const parsed = SubmitAuditSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parsed.error.format() });
  }

  const { source, solcVersion, publish } = parsed.data;
  let { tools, enableFuzzing } = parsed.data;

  // Publish-by-default, but only for signed-in users — anonymous audits are
  // never auto-listed in the public registry. `publish !== false` keeps the
  // default on when the flag is omitted.
  const autoPublish = publish !== false && !!req.userId;

  // Anonymous users can't trigger the expensive opt-in engines — Echidna fuzzing
  // can run for minutes and gigabytes. Gate those behind a signed-in account.
  if (!req.userId) {
    enableFuzzing = false;
    if (tools) tools = tools.filter(t => t !== 'echidna');
    // Cap anonymous paste size: 512KB is plenty of real Solidity; the 2MB schema
    // ceiling is reserved for signed-in users (flattened multi-file repos).
    if (source.type === 'paste' && source.code.length > ANON_PASTE_MAX_BYTES) {
      return res.status(413).json({
        error: `Anonymous submissions are limited to ${Math.round(ANON_PASTE_MAX_BYTES / 1000)}KB of source. Sign in to audit larger contracts, or scan by address / GitHub repo.`,
      });
    }
  }
  // Backpressure: refuse new work when the queue is already deep, so a burst of
  // submissions can't pile up faster than the worker (concurrency 2) drains it.
  if ((await auditQueue.getWaitingCount()) > 30) {
    return res.status(429).json({ error: 'The audit queue is busy right now — please retry in a minute.' });
  }

  let code: string;
  let resolvedSource: Record<string, unknown> = {};

  try {
    if (source.type === 'paste') {
      code = source.code;
      resolvedSource = { type: 'paste', label: source.filename || 'pasted-source' };
    } else if (source.type === 'address') {
      const fetched = await fetchEtherscanSource(source.address, source.chain);
      code = fetched.flattenedSource;
      resolvedSource = {
        type: 'address',
        label: `${source.chain}:${source.address}`,
        address: source.address,
        chain: source.chain,
        contractName: fetched.contractName,
        solcVersion: fetched.compilerVersion,
      };
    } else {
      const fetched = await fetchGithubSource(source.repo, source.path, source.ref);
      code = fetched.flattenedSource;
      resolvedSource = {
        type: 'github',
        label: `github:${source.repo}/${source.path}`,
        repo: source.repo,
        path: source.path,
        ref: source.ref,
      };
    }
  } catch (e) {
    return res.status(400).json({
      error: 'Could not resolve source',
      details: e instanceof Error ? e.message : String(e),
    });
  }

  const auditId = randomUUID();
  await auditQueue.add('audit', {
    auditId,
    code,
    source: resolvedSource,
    tools,
    solcVersion,
    enableFuzzing,
    // Record the submitting user (anonymous submissions get undefined)
    ownerId: req.userId,
    autoPublish,
  }, {
    jobId: auditId,
    attempts: 1,
    removeOnComplete: { count: 1000 },
    removeOnFail: { count: 500 },
  });

  res.status(202).json({
    id: auditId,
    status: 'queued',
    pollUrl: `/api/audits/${auditId}`,
  });
}));

/**
 * GET /api/audits/:id
 * Returns the report if complete, otherwise the job status.
 */
app.get('/api/audits/:id', asyncHandler(async (req, res) => {
  const report = await getReport(req.params.id);
  if (report) {
    const published = await isReportPublished(req.params.id).catch(() => false);
    return res.json({ status: 'complete', report, published });
  }

  const job = await auditQueue.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Not found' });

  const state = await job.getState();
  res.json({
    status: state,
    progress: job.progress,
    failedReason: job.failedReason,
  });
}));

/**
 * GET /api/audits/:id/pdf
 */
app.get('/api/audits/:id/pdf', asyncHandler(async (req, res) => {
  const report = await getReport(req.params.id);
  if (!report) return res.status(404).json({ error: 'Not found' });
  const pdfBuffer = await buildPdf(report);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="forensiq-${report.id}.pdf"`);
  res.send(pdfBuffer);
}));

/**
 * GET /api/audits  — list recent (for dashboard)
 */
app.get('/api/audits', asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
  const reports = await listReports(limit);
  res.json({ reports });
}));

// ─── Error handler ───────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[API ERROR]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Boot ────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[forensiq-api] listening on :${PORT}`);
  console.log(`[forensiq-api] redis: ${REDIS_URL}`);
});

process.on('SIGTERM', async () => {
  console.log('[forensiq-api] shutting down');
  await connection.quit();
  process.exit(0);
});
