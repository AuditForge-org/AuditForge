/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — Authentication.
 *
 * Two layers:
 *
 *   1. GitHub OAuth — the user clicks "Sign in with GitHub", we redirect
 *      to GitHub with our Client ID, GitHub redirects back with a code,
 *      we exchange it for a GitHub access token, look up the user, and
 *      create or update their row in our `users` table.
 *
 *   2. Session JWT — we issue our own short-lived JWT (HS256, 7-day TTL)
 *      that the frontend stores in an HttpOnly cookie. Every request
 *      passes through `requireAuth` which validates the JWT and attaches
 *      the user to req.
 *
 * Why HS256 instead of RS256 for sessions: we control both signing and
 * verification (single backend), there's no third-party verifier, and
 * HMAC is faster. Production deployments should rotate SESSION_SECRET
 * periodically — use a key id (`kid`) header if you need overlap.
 *
 * Why HttpOnly cookies instead of Authorization headers: CSRF risk on
 * cookies, XSS risk on localStorage. Cookies win for SPAs that need
 * SSR-friendly auth, plus they survive page reloads without JS. We
 * mitigate CSRF with SameSite=Lax.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { sign, verify, JwtPayload } from 'jsonwebtoken';
import { randomBytes, createHmac, timingSafeEqual } from 'crypto';
import { upsertUserFromGithub, getUserById, User } from '../db/users';
import { claimInstallation } from '../db/installations';
import { RATE_LIMITS } from '../middleware/ratelimit';

const OAUTH_CLIENT_ID = process.env.GITHUB_OAUTH_CLIENT_ID || '';
const OAUTH_CLIENT_SECRET = process.env.GITHUB_OAUTH_CLIENT_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3000';
const FRONTEND_URL = process.env.FRONTEND_URL || PUBLIC_URL;
const COOKIE_NAME = 'forensiq_session';
const SESSION_TTL_DAYS = 7;

export function isAuthConfigured(): boolean {
  return !!(OAUTH_CLIENT_ID && OAUTH_CLIENT_SECRET && SESSION_SECRET);
}

interface SessionPayload extends JwtPayload {
  uid: string;        // our internal user id
  gid: number;        // github user id (for cross-ref to installations)
  uname: string;      // github username (for display, not security)
}

// ─── JWT helpers ─────────────────────────────────────────────────────

function issueSession(user: User): string {
  return sign(
    { uid: user.id, gid: user.githubUserId, uname: user.githubUsername },
    SESSION_SECRET,
    { algorithm: 'HS256', expiresIn: `${SESSION_TTL_DAYS}d`, issuer: 'forensiq' }
  );
}

function verifySession(token: string): SessionPayload | null {
  try {
    return verify(token, SESSION_SECRET, {
      algorithms: ['HS256'],
      issuer: 'forensiq',
    }) as SessionPayload;
  } catch {
    return null;
  }
}

// ─── CSRF-resistant OAuth state ──────────────────────────────────────

/**
 * We sign the `state` parameter passed to GitHub so we can verify it on
 * callback without server-side session storage. The signature is HMAC
 * with SESSION_SECRET; the state body includes a nonce + timestamp.
 *
 * This protects against attackers initiating an OAuth flow on a victim's
 * behalf (login CSRF). The state must round-trip intact and be fresh.
 */
function signState(returnTo: string): string {
  const nonce = randomBytes(16).toString('hex');
  const ts = Date.now().toString(36);
  const payload = `${nonce}.${ts}.${encodeURIComponent(returnTo)}`;
  const sig = createHmac('sha256', SESSION_SECRET).update(payload).digest('hex').slice(0, 32);
  return `${payload}.${sig}`;
}

function verifyState(state: string, maxAgeMs = 10 * 60 * 1000): { returnTo: string } | null {
  const parts = state.split('.');
  if (parts.length !== 4) return null;
  const [nonce, ts, returnToEnc, sig] = parts;
  const expected = createHmac('sha256', SESSION_SECRET)
    .update(`${nonce}.${ts}.${returnToEnc}`)
    .digest('hex').slice(0, 32);
  // Timing-safe compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  const age = Date.now() - parseInt(ts, 36);
  if (age < 0 || age > maxAgeMs) return null;
  return { returnTo: decodeURIComponent(returnToEnc) };
}

// ─── Cookie helpers ──────────────────────────────────────────────────

function setSessionCookie(res: Response, token: string): void {
  // Secure: only over HTTPS. We allow plain http on localhost for dev.
  const secure = !PUBLIC_URL.startsWith('http://localhost');
  const maxAge = SESSION_TTL_DAYS * 24 * 60 * 60;
  const parts = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res: Response): void {
  const secure = !PUBLIC_URL.startsWith('http://localhost');
  const parts = [
    `${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0',
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function readSessionCookie(req: Request): string | null {
  const cookie = req.header('cookie');
  if (!cookie) return null;
  for (const part of cookie.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k === COOKIE_NAME) return v;
  }
  return null;
}

// ─── Express middleware ──────────────────────────────────────────────

/**
 * `requireAuth` rejects with 401 if there's no valid session.
 * `optionalAuth` populates req.user if there is one but doesn't reject.
 *
 * Both attach `req.user` and `req.userId` for handlers to use.
 */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: User;
      userId?: string;
    }
  }
}

export async function optionalAuth(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const token = readSessionCookie(req);
  if (token) {
    const payload = verifySession(token);
    if (payload?.uid) {
      // Fetching the user every request is the price of having a single
      // source of truth (plan changes, suspension etc. take effect immediately).
      // For high-traffic apps cache this in Redis with a short TTL.
      const user = await getUserById(payload.uid);
      if (user) {
        req.user = user;
        req.userId = user.id;
      }
    }
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required', loginUrl: '/api/auth/github/login' });
    return;
  }
  next();
}

// ─── OAuth routes ────────────────────────────────────────────────────

const router = Router();

/**
 * GET /api/auth/github/login?returnTo=/some/path
 * Redirects to GitHub authorize endpoint.
 */
router.get('/github/login', RATE_LIMITS.auth, (req: Request, res: Response) => {
  if (!isAuthConfigured()) {
    return res.status(503).json({ error: 'Auth not configured on this server' });
  }
  const returnTo = (req.query.returnTo as string) || '/';
  const state = signState(returnTo);
  const params = new URLSearchParams({
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: `${PUBLIC_URL}/api/auth/github/callback`,
    // 'read:user' is enough — we don't need repo access from the OAuth
    // App because the GitHub App handles repo data with its own creds.
    scope: 'read:user user:email',
    state,
    allow_signup: 'true',
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

/**
 * GET /api/auth/github/callback
 * GitHub redirects here after the user authorizes. We:
 *   1. Verify state matches what we issued (CSRF check)
 *   2. Exchange code for a GitHub access token
 *   3. Fetch the GitHub user profile + email
 *   4. Upsert our user row
 *   5. Auto-claim any pending installations under the same GitHub login
 *   6. Issue our session JWT + redirect to returnTo
 */
router.get('/github/callback', RATE_LIMITS.auth, async (req: Request, res: Response) => {
  if (!isAuthConfigured()) {
    return res.status(503).json({ error: 'Auth not configured' });
  }

  const { code, state, error: oauthError } = req.query;
  if (oauthError) return res.redirect(`${FRONTEND_URL}/#/login?error=${encodeURIComponent(String(oauthError))}`);
  if (!code || !state) return res.status(400).json({ error: 'Missing code or state' });

  const verified = verifyState(String(state));
  if (!verified) return res.status(400).json({ error: 'Invalid or expired state' });

  // Exchange code for access token
  let accessToken: string;
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: OAUTH_CLIENT_ID,
        client_secret: OAUTH_CLIENT_SECRET,
        code: String(code),
        redirect_uri: `${PUBLIC_URL}/api/auth/github/callback`,
      }),
    });
    const tokenData = (await tokenRes.json()) as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      return res.status(400).json({ error: 'Token exchange failed', detail: tokenData.error });
    }
    accessToken = tokenData.access_token;
  } catch (e) {
    return res.status(502).json({ error: 'Token exchange request failed', detail: (e as Error).message });
  }

  // Fetch user profile
  const ghHeaders = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'forensiq',
  };

  let ghUser: { id: number; login: string; email: string | null; avatar_url: string };
  try {
    const userRes = await fetch('https://api.github.com/user', { headers: ghHeaders });
    if (!userRes.ok) throw new Error(`user fetch ${userRes.status}`);
    ghUser = await userRes.json() as typeof ghUser;
  } catch (e) {
    return res.status(502).json({ error: 'GitHub user fetch failed', detail: (e as Error).message });
  }

  // Email may be private. Try the emails endpoint if missing.
  let email = ghUser.email;
  if (!email) {
    try {
      const emailRes = await fetch('https://api.github.com/user/emails', { headers: ghHeaders });
      if (emailRes.ok) {
        const emails = (await emailRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
        const primary = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
        email = primary?.email || null;
      }
    } catch { /* non-fatal */ }
  }

  // Upsert user
  const user = await upsertUserFromGithub({
    githubUserId: ghUser.id,
    githubUsername: ghUser.login,
    email: email || undefined,
    avatarUrl: ghUser.avatar_url,
  });

  // Auto-claim any GitHub App installation under the same account
  // (best-effort; installation_id may not be exposed in the OAuth flow).
  try {
    await claimInstallationsForLogin(ghUser.login, user.id);
  } catch (e) {
    console.warn('[auth] claim installations failed:', (e as Error).message);
  }

  // Issue session
  const session = issueSession(user);
  setSessionCookie(res, session);

  // Bounce to frontend
  const returnUrl = verified.returnTo.startsWith('/')
    ? `${FRONTEND_URL}${verified.returnTo}`
    : FRONTEND_URL;
  res.redirect(returnUrl);
});

/**
 * Find any installations created under the user's GitHub login and link them
 * to the just-logged-in Forensiq user. This is what makes the "install App,
 * then sign in" UX seamless — the user's installations get bound to their
 * account automatically.
 */
async function claimInstallationsForLogin(login: string, userId: string): Promise<void> {
  const { Pool } = await import('pg');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL ||
      'postgres://forensiq:forensiq@localhost:5432/forensiq',
  });
  const res = await pool.query(
    `SELECT installation_id FROM github_installations
     WHERE owner_id IS NULL AND lower(account_login) = lower($1)`,
    [login]
  );
  for (const row of res.rows) {
    await claimInstallation(Number(row.installation_id), userId);
  }
  await pool.end();
}

/**
 * GET /api/auth/me
 * Returns the current user, or 401 if not authenticated.
 */
router.get('/me', optionalAuth, (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  // Don't expose all DB fields blindly — return only what the frontend needs.
  res.json({
    user: {
      id: req.user.id,
      githubUsername: req.user.githubUsername,
      email: req.user.email,
      avatarUrl: req.user.avatarUrl,
      plan: req.user.plan,
    },
  });
});

/**
 * POST /api/auth/logout
 * Clears the session cookie.
 */
router.post('/logout', (_req: Request, res: Response) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

export default router;
