# Authentication setup

Forensiq uses GitHub OAuth for user login and signed session cookies for state.

> **OAuth App vs. GitHub App** — these are two separate things on GitHub. You need *both*. The OAuth App handles user identity (who is logged in). The GitHub App (see `github-app.md`) handles repo operations (checks, PR comments, code fetching). They have independent credentials.

## 1. Register the OAuth App

Go to https://github.com/settings/applications/new (personal) or
https://github.com/organizations/YOUR-ORG/settings/applications/new (org).

| Field | Value |
|---|---|
| **Application name** | `Forensiq` (or `Forensiq Dev` for a separate dev OAuth App) |
| **Homepage URL** | `https://forensiq.example.com` |
| **Authorization callback URL** | `https://forensiq.example.com/api/auth/github/callback` |
| **Enable Device Flow** | No |

Submit. You'll see a **Client ID** and a button to **Generate a new client secret**.

## 2. Generate session secret

```bash
openssl rand -hex 32
```

This is the HMAC signing key for session JWTs and OAuth state parameters. Keep it in `.env`, never commit it. Rotating it logs out every user (their existing tokens fail verification), which is the right behavior.

## 3. Configure backend

Add to `.env`:

```env
GITHUB_OAUTH_CLIENT_ID=Iv1.xxxxxxxx
GITHUB_OAUTH_CLIENT_SECRET=...
SESSION_SECRET=<the 64-hex output from step 2>
PUBLIC_URL=https://forensiq.example.com
FRONTEND_URL=https://forensiq.example.com   # set explicitly if frontend is on a different host
```

Restart the API. From the browser, hitting `/api/auth/github/login` should now redirect to GitHub.

## How it works

```
                  Browser              Forensiq               GitHub
                   |                     |                     |
  click Sign In →  |─ GET /login ────────▶                     |
                   |                     |─ sign state ────────|
                   |  ◀── 302 ─ to GitHub authorize URL ──────|
                   |─────────────────────────────────────────▶|
                   |                                          |
                   |  user clicks Authorize on GitHub          |
                   |                                          |
                   |  ◀── 302 ─ /callback?code=...&state=... ─|
                   |─ GET /callback ─────▶                     |
                   |                     |─ verify state ──────|
                   |                     |─ exchange code ─────▶|
                   |                     |  ◀── access_token ──|
                   |                     |─ fetch user ────────▶|
                   |                     |  ◀── { id, login }──|
                   |                     |─ upsert user ───────|
                   |                     |─ claim installs ────|
                   |                     |─ issue JWT ─────────|
                   |  ◀── 302 + Set-Cookie ──────────────────  |
```

Then on every subsequent request:

```
  ─ Cookie: forensiq_session=eyJhbGc... ──▶
  ─ optionalAuth verifies + loads user ───
  ─ req.user / req.userId populated ───
  ─ requireAuth rejects with 401 if missing ─
```

## Security properties

| Threat | Mitigation |
|---|---|
| Login CSRF (attacker initiates OAuth on victim's session) | Signed `state` parameter with HMAC + timestamp + nonce |
| Replay of old state | 10-minute expiry on state |
| `alg:none` JWT attack | `algorithms: ['HS256']` locked in verify call |
| Session theft via XSS | HttpOnly cookie (JS can't read it) |
| Cookie sent to attacker site | SameSite=Lax |
| MITM cookie sniff | Secure flag set when not on localhost |
| Wrong-issuer JWT | `issuer: 'forensiq'` enforced on verify |
| Stolen secret reuse | Rotate `SESSION_SECRET` to invalidate everything |
| Username collision on rename | Upsert keyed by stable `github_user_id`, not username |

The CSRF for *post-login* mutations relies on SameSite=Lax (set automatically). For browsers without SameSite support or for highly sensitive endpoints, add a double-submit CSRF token middleware — not required for the current threat model since OAuth-only login means no credentials transit our origin.

## Auto-claim of GitHub App installations

If a user installs the Forensiq GitHub App **before** they log in (common — they discover the App on the marketplace), the `github_installations.owner_id` column starts as NULL. When the user later signs in via OAuth, we run:

```sql
UPDATE github_installations
SET owner_id = $userId
WHERE owner_id IS NULL AND lower(account_login) = lower($githubLogin)
```

This binds their pending installation to their account so they see it on `/watch`. The login match is case-insensitive (GitHub usernames are).

## Anonymous submissions

Reports submitted without a logged-in user are persisted with `owner_id = NULL`. They:

- Can be **viewed** by anyone with the URL (no access control on read)
- Can **not be published** to the registry (publish requires ownership)
- Can **not be associated** to a user later (we don't have anything to match on)

If you want to claim an anonymous report retroactively, you'd need to add an "ownership token" returned at submission time. Not currently implemented.

## Troubleshooting

**`{"error": "Auth not configured on this server"}`** — One or more of `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `SESSION_SECRET` is missing from `.env`.

**`{"error": "Invalid or expired state"}`** — The state parameter didn't survive the GitHub round-trip, was tampered with, or took more than 10 minutes. Most common cause: you registered the OAuth App's callback URL incorrectly, so GitHub redirects to a different host that doesn't share the SESSION_SECRET.

**Cookie not sent on subsequent requests** — Cross-origin setup with missing CORS config. Check that the backend sees `Origin: ${FRONTEND_URL}` and that the CORS middleware was configured with `credentials: true`. In the browser DevTools, the `Set-Cookie` header should have the right `Domain` (or none — domain-less cookies default to the response host).

**"Sign In" button does nothing in local dev** — You're probably on `http://localhost` and the cookie's `Secure` flag is making it non-functional. The backend already disables `Secure` when `PUBLIC_URL` starts with `http://localhost`. Verify your env var.

**User logs in but `/api/auth/me` returns 401** — Means the cookie is set but not being sent back. Almost always: frontend on a different host than backend, and `fetch` is missing `credentials: 'include'`. Check `frontend/api.js` — the bundled version already has this.
