// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * FORENSIQ — Redis-backed rate limiter.
 *
 * Sliding-window algorithm: for each key, we maintain a sorted set of
 * request timestamps. Each request adds itself and removes entries
 * older than the window, then counts remaining entries.
 *
 * Using a Lua script makes the read-decide-write atomic — without it,
 * two concurrent requests at the boundary could both pass the count
 * check before either increments.
 *
 * Fallback: if Redis is unreachable, we fail open (allow the request)
 * and log a warning. Failing closed on a Redis outage would take down
 * the whole API. This matches industry practice — rate limiting is a
 * defense, not a hard correctness requirement.
 *
 * Key naming: `rl:<scope>:<id>` so different limits don't collide.
 */

import { Request, Response, NextFunction } from 'express';
import IORedis, { Redis } from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// Dedicated connection — separate from BullMQ so a busy queue doesn't
// starve the rate limiter (and vice versa).
let client: Redis | null = null;
function getClient(): Redis {
  if (!client) {
    client = new IORedis(REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      lazyConnect: false,
    });
    client.on('error', (e) => {
      // Don't crash on transient connectivity — the middleware fails open.
      // We just log at most once per minute to avoid noise.
      if (!recentErrorLog || Date.now() - recentErrorLog > 60_000) {
        console.warn('[ratelimit] redis error:', e.message);
        recentErrorLog = Date.now();
      }
    });
  }
  return client;
}
let recentErrorLog = 0;

/**
 * Sliding-window Lua script.
 *
 * KEYS[1] = the sorted-set key
 * ARGV[1] = current epoch ms
 * ARGV[2] = window size ms
 * ARGV[3] = max allowed in window
 * ARGV[4] = unique request id (so two requests at the same ms don't collide)
 *
 * Returns: { allowed (1|0), count, ttl }
 */
const SLIDING_WINDOW_SCRIPT = `
  local now = tonumber(ARGV[1])
  local window = tonumber(ARGV[2])
  local max = tonumber(ARGV[3])
  local id = ARGV[4]
  local cutoff = now - window

  -- Drop entries outside the window
  redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, cutoff)
  local count = redis.call('ZCARD', KEYS[1])

  if count >= max then
    return {0, count, window}
  end

  redis.call('ZADD', KEYS[1], now, id)
  -- Auto-expire the whole key once it's older than the window so we don't
  -- leak memory on infrequently-accessed keys.
  redis.call('PEXPIRE', KEYS[1], window)
  return {1, count + 1, window}
`;

let scriptSha: string | null = null;
async function ensureScript(redis: Redis): Promise<string> {
  if (scriptSha) return scriptSha;
  scriptSha = await redis.script('LOAD', SLIDING_WINDOW_SCRIPT) as string;
  return scriptSha;
}

export interface RateLimitOptions {
  scope: string;           // e.g. 'api', 'audit-submit', 'login'
  max: number | ((req: Request) => number);  // requests per window (may depend on the request)
  windowMs: number;        // window size
  /** Function to derive the rate-limit key from the request (default: IP) */
  keyFn?: (req: Request) => string;
  /** Skip rate-limiting for certain requests (e.g. authenticated users) */
  skipFn?: (req: Request) => boolean;
}

function defaultKey(req: Request): string {
  // Prefer the authenticated user id if available — fair to bots vs humans
  if (req.userId) return `user:${req.userId}`;
  // Use the leftmost IP from X-Forwarded-For (the original client), with
  // fallback to direct connection. In k8s behind an ingress this header
  // is set by the ingress controller.
  const xff = req.header('x-forwarded-for');
  const ip = xff?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || 'unknown';
  return `ip:${ip}`;
}

export function rateLimit(opts: RateLimitOptions) {
  return async function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
    if (opts.skipFn?.(req)) return next();

    const key = `rl:${opts.scope}:${(opts.keyFn || defaultKey)(req)}`;
    const reqId = `${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
    const max = typeof opts.max === 'function' ? opts.max(req) : opts.max;

    try {
      const redis = getClient();
      const sha = await ensureScript(redis);
      const result = await redis.evalsha(
        sha, 1, key,
        String(Date.now()), String(opts.windowMs), String(max), reqId,
      ) as [number, number, number];

      const [allowed, count] = result;
      // Standard rate-limit headers (RFC 6585 + draft-ietf-httpapi-ratelimit-headers)
      res.setHeader('X-RateLimit-Limit', String(max));
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - count)));
      // Per-scope header so each limiter's resolved cap is observable even when
      // several limiters run on one route (they'd otherwise clobber the generic one).
      res.setHeader(`X-RateLimit-${opts.scope}`, String(max));

      if (!allowed) {
        res.setHeader('Retry-After', String(Math.ceil(opts.windowMs / 1000)));
        return res.status(429).json({
          error: 'Rate limit exceeded',
          retryAfter: Math.ceil(opts.windowMs / 1000),
        });
      }
      next();
    } catch (e) {
      // Fail open on Redis errors — see module-level comment for rationale
      if ((e as Error).message.includes('NOSCRIPT')) {
        // Script cache was flushed; reload and retry once
        scriptSha = null;
        try {
          await ensureScript(getClient());
          return rateLimitMiddleware(req, res, next);
        } catch {}
      }
      next();
    }
  };
}

/** Pre-configured limits for common scopes. */
export const RATE_LIMITS = {
  // General API: 60/min/IP, generous for browsing
  api: rateLimit({ scope: 'api', max: 60, windowMs: 60_000 }),
  // Audit submission: 8/hour per real client IP (trust-proxy makes req.ip correct).
  // It's an expensive op — kept low; raise the user bucket once OAuth is enabled.
  auditSubmit: rateLimit({
    scope: 'audit',
    max: 8,
    windowMs: 60 * 60_000,
    keyFn: (req) => req.userId ? `user:${req.userId}` : `ip:${req.ip}`,
    skipFn: (_req) => false,
  }),
  // Daily ceiling per client. Signed-in users get 6/day; anonymous users get
  // 1/day — but ONLY once GitHub sign-in is actually available (OAuth configured),
  // so we never trap anon users at 1/day with no way to raise it. Until then,
  // anon keeps the same 6/day as signed-in.
  auditDaily: rateLimit({
    scope: 'audit-day',
    max: (req) => req.userId ? 6 : (process.env.GITHUB_OAUTH_CLIENT_ID ? 1 : 6),
    windowMs: 24 * 60 * 60_000,
    keyFn: (req) => req.userId ? `user:${req.userId}` : `ip:${req.ip}`,
  }),
  // Auth endpoints (login start, callback): 20/min/IP — protects against
  // OAuth abuse and brute-force-style state guessing
  auth: rateLimit({ scope: 'auth', max: 20, windowMs: 60_000 }),
};
