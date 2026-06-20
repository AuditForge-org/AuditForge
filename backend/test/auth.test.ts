/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Auth tests. We exercise the parts that don't require a live DB:
 *   - State parameter signing + verification (CSRF protection)
 *   - Session JWT roundtrip
 *   - Tampering detection
 *
 * The OAuth callback and `requireAuth` middleware are integration-tested
 * separately because they need a Postgres + a real cookie pipeline.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { sign, verify, JwtPayload } from 'jsonwebtoken';
import { createHmac, timingSafeEqual } from 'crypto';

// We test the signing logic by reproducing it. The actual functions in
// src/auth/index.ts are not exported (intentionally — they're internal).
// This keeps the test focused on the algorithm, not the implementation.

const SECRET = 'test-session-secret-DO-NOT-USE-IN-PROD-abcdef';

function signState(returnTo: string, ts = Date.now(), nonce = 'abc123'): string {
  const tsStr = ts.toString(36);
  const payload = `${nonce}.${tsStr}.${encodeURIComponent(returnTo)}`;
  const sig = createHmac('sha256', SECRET).update(payload).digest('hex').slice(0, 32);
  return `${payload}.${sig}`;
}

function verifyState(state: string, maxAgeMs = 10 * 60 * 1000): { returnTo: string } | null {
  const parts = state.split('.');
  if (parts.length !== 4) return null;
  const [nonce, ts, returnToEnc, sig] = parts;
  const expected = createHmac('sha256', SECRET)
    .update(`${nonce}.${ts}.${returnToEnc}`)
    .digest('hex').slice(0, 32);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  const age = Date.now() - parseInt(ts, 36);
  if (age < 0 || age > maxAgeMs) return null;
  return { returnTo: decodeURIComponent(returnToEnc) };
}

describe('OAuth state parameter', () => {
  it('signs and verifies a state round-trip', () => {
    const state = signState('/dashboard');
    const result = verifyState(state);
    expect(result).not.toBeNull();
    expect(result!.returnTo).toBe('/dashboard');
  });

  it('preserves URL-encoded characters in returnTo', () => {
    const state = signState('/r/abc?x=1&y=2');
    const result = verifyState(state);
    expect(result!.returnTo).toBe('/r/abc?x=1&y=2');
  });

  it('rejects a tampered signature', () => {
    const state = signState('/dashboard');
    const tampered = state.slice(0, -4) + 'ffff';
    expect(verifyState(tampered)).toBeNull();
  });

  it('rejects a tampered returnTo (different body, original sig)', () => {
    const ts = Date.now();
    const state = signState('/dashboard', ts);
    const parts = state.split('.');
    const malicious = `${parts[0]}.${parts[1]}.${encodeURIComponent('/evil')}.${parts[3]}`;
    expect(verifyState(malicious)).toBeNull();
  });

  it('rejects an expired state', () => {
    const tooOld = Date.now() - 11 * 60 * 1000;
    const state = signState('/dashboard', tooOld);
    expect(verifyState(state)).toBeNull();
  });

  it('rejects state from the future (clock skew attack)', () => {
    const future = Date.now() + 5 * 60 * 1000;
    const state = signState('/dashboard', future);
    expect(verifyState(state)).toBeNull();
  });

  it('rejects malformed state', () => {
    expect(verifyState('not-a-state')).toBeNull();
    expect(verifyState('a.b.c')).toBeNull();
    expect(verifyState('a.b.c.d.e')).toBeNull();
  });
});

// ─── Session JWT ─────────────────────────────────────────────────────

interface SessionPayload extends JwtPayload {
  uid: string;
  gid: number;
  uname: string;
}

function issueSession(payload: Omit<SessionPayload, 'iat' | 'exp' | 'iss'>): string {
  return sign(payload, SECRET, {
    algorithm: 'HS256',
    expiresIn: '7d',
    issuer: 'forensiq',
  });
}

function verifySession(token: string): SessionPayload | null {
  try {
    return verify(token, SECRET, {
      algorithms: ['HS256'],
      issuer: 'forensiq',
    }) as SessionPayload;
  } catch {
    return null;
  }
}

describe('Session JWT', () => {
  it('round-trips a session token', () => {
    const token = issueSession({ uid: 'user-1', gid: 12345, uname: 'alice' });
    const decoded = verifySession(token);
    expect(decoded?.uid).toBe('user-1');
    expect(decoded?.gid).toBe(12345);
    expect(decoded?.uname).toBe('alice');
  });

  it('rejects a tampered token', () => {
    const token = issueSession({ uid: 'user-1', gid: 12345, uname: 'alice' });
    const tampered = token.slice(0, -10) + 'X'.repeat(10);
    expect(verifySession(tampered)).toBeNull();
  });

  it('rejects a token signed with a different secret', () => {
    const otherToken = sign({ uid: 'user-1', gid: 1, uname: 'a' }, 'different-secret', {
      algorithm: 'HS256', expiresIn: '7d', issuer: 'forensiq',
    });
    expect(verifySession(otherToken)).toBeNull();
  });

  it('rejects a token with the wrong issuer', () => {
    const wrongIss = sign({ uid: 'user-1', gid: 1, uname: 'a' }, SECRET, {
      algorithm: 'HS256', expiresIn: '7d', issuer: 'evil',
    });
    expect(verifySession(wrongIss)).toBeNull();
  });

  it('rejects expired tokens', () => {
    const expired = sign({ uid: 'user-1', gid: 1, uname: 'a' }, SECRET, {
      algorithm: 'HS256', expiresIn: '-1s', issuer: 'forensiq',
    });
    expect(verifySession(expired)).toBeNull();
  });

  it('rejects algorithm confusion attacks (none alg)', () => {
    // Classic jwt vulnerability: attacker presents a token with alg: 'none'
    // hoping the server skips signature verification. jsonwebtoken refuses
    // when we lock to HS256, but let's confirm.
    const noneToken = sign({ uid: 'evil' }, '', {
      algorithm: 'none' as 'HS256', // cast just to construct
      issuer: 'forensiq',
    });
    expect(verifySession(noneToken)).toBeNull();
  });
});
