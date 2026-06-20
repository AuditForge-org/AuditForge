/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * FORENSIQ — GitHub App authentication.
 *
 * A GitHub App authenticates in two layers:
 *
 *   1. App-level JWT: signed with the App's private key (RS256), proves
 *      "I am the Forensiq GitHub App". Used to list installations and
 *      mint installation tokens. Short-lived (10 min max per GitHub).
 *
 *   2. Installation token: scoped to a specific installation on a user
 *      or org. Used for actual repo operations (creating check runs,
 *      posting comments, reading file contents). 1-hour lifetime.
 *
 * We cache installation tokens in memory keyed by installation ID, with
 * a safety margin (refresh 5 minutes before expiry). For multi-instance
 * deployments, move this cache to Redis.
 *
 * Reference:
 *   https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app
 */

import { createPrivateKey, KeyObject } from 'crypto';
import { sign } from 'jsonwebtoken';

const APP_ID = process.env.GITHUB_APP_ID;
const APP_PRIVATE_KEY = process.env.GITHUB_APP_PRIVATE_KEY;  // PEM
const APP_WEBHOOK_SECRET = process.env.GITHUB_APP_WEBHOOK_SECRET;

interface CachedToken {
  token: string;
  expiresAt: number;          // epoch ms
  repositorySelection: 'all' | 'selected';
  permissions: Record<string, string>;
}

const tokenCache = new Map<number, CachedToken>();

let cachedKey: KeyObject | null = null;
function loadPrivateKey(): KeyObject {
  if (cachedKey) return cachedKey;
  if (!APP_PRIVATE_KEY) {
    throw new Error('GITHUB_APP_PRIVATE_KEY not set. Cannot sign GitHub App JWTs.');
  }
  // Allow both raw PEM and base64-encoded PEM in env (some hosts mangle newlines)
  const pem = APP_PRIVATE_KEY.includes('BEGIN')
    ? APP_PRIVATE_KEY
    : Buffer.from(APP_PRIVATE_KEY, 'base64').toString('utf8');
  cachedKey = createPrivateKey({ key: pem, format: 'pem' });
  return cachedKey;
}

/**
 * Create a short-lived app-level JWT. Per GitHub docs the `exp` must be
 * within 10 minutes of `iat` and clocks can be off by ~30s — we use 8 min
 * with a -30s iat to be safe.
 */
export function createAppJwt(): string {
  if (!APP_ID) throw new Error('GITHUB_APP_ID not set');
  const now = Math.floor(Date.now() / 1000);
  return sign(
    {
      iat: now - 30,
      exp: now + 8 * 60,
      iss: APP_ID,
    },
    loadPrivateKey() as unknown as string,  // jsonwebtoken accepts KeyObject
    { algorithm: 'RS256' }
  );
}

interface InstallationTokenResponse {
  token: string;
  expires_at: string;         // ISO
  permissions: Record<string, string>;
  repository_selection: 'all' | 'selected';
}

/**
 * Get an installation access token, using cache when valid.
 *
 * GitHub returns tokens with a 1-hour TTL. We refresh when remaining
 * lifetime is under 5 minutes — this keeps us safe from clock skew and
 * long-running operations that might otherwise hold a stale token.
 */
export async function getInstallationToken(installationId: number): Promise<string> {
  const cached = tokenCache.get(installationId);
  const safetyMarginMs = 5 * 60 * 1000;
  if (cached && cached.expiresAt > Date.now() + safetyMarginMs) {
    return cached.token;
  }

  const jwt = createAppJwt();
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'forensiq-github-app',
      },
    }
  );

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Failed to mint installation token: ${res.status} ${body}`);
  }

  const data = (await res.json()) as InstallationTokenResponse;
  const expiresAt = new Date(data.expires_at).getTime();

  tokenCache.set(installationId, {
    token: data.token,
    expiresAt,
    repositorySelection: data.repository_selection,
    permissions: data.permissions,
  });

  return data.token;
}

/**
 * Convenience: list installations for the App. Used by the bootstrap
 * flow when a user comes back from the "Install" redirect — we can
 * resolve their installation id by matching the account.
 */
export async function listInstallations(): Promise<Array<{
  id: number;
  account: { login: string; type: 'User' | 'Organization' };
  repository_selection: 'all' | 'selected';
}>> {
  const jwt = createAppJwt();
  const res = await fetch('https://api.github.com/app/installations', {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'forensiq-github-app',
    },
  });
  if (!res.ok) throw new Error(`Failed to list installations: ${res.status}`);
  return res.json() as Promise<Array<{
    id: number;
    account: { login: string; type: 'User' | 'Organization' };
    repository_selection: 'all' | 'selected';
  }>>;
}

/**
 * Resolve installation id from owner login. The GitHub App must be
 * installed on that account.
 */
export async function findInstallationFor(owner: string): Promise<number | null> {
  const installations = await listInstallations();
  const match = installations.find(
    i => i.account.login.toLowerCase() === owner.toLowerCase()
  );
  return match?.id ?? null;
}

export function getWebhookSecret(): string {
  if (!APP_WEBHOOK_SECRET) {
    throw new Error('GITHUB_APP_WEBHOOK_SECRET not set');
  }
  return APP_WEBHOOK_SECRET;
}

export function isConfigured(): boolean {
  return !!(APP_ID && APP_PRIVATE_KEY && APP_WEBHOOK_SECRET);
}
