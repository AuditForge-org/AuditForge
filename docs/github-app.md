# GitHub App setup

This document explains how to register and deploy the Forensiq GitHub App, which provides:

- **Check runs** — Forensiq audit status appears next to commits and PRs (red ✗ / green ✓)
- **PR comments** — findings posted as a single, in-place updated comment
- **One-click install** — users install once per account/org, no per-project secrets
- **Multi-repo coverage** — users pick "all repos" or a selected subset at install time

## 1. Register the App

Go to https://github.com/settings/apps/new (for a personal account) or
https://github.com/organizations/YOUR-ORG/settings/apps/new (for an org).

Fill in:

| Field | Value |
|---|---|
| **GitHub App name** | `Forensiq` (or `Forensiq-Staging` for a test instance) |
| **Homepage URL** | `https://forensiq.example.com` |
| **Callback URL** | `https://forensiq.example.com/auth/github/callback` (when you add OAuth later) |
| **Setup URL** | `https://forensiq.example.com/install-success` (optional) |
| **Webhook URL** | `https://forensiq.example.com/api/gh/app` |
| **Webhook secret** | Generate a strong random string (32+ chars). You'll set this as `GITHUB_APP_WEBHOOK_SECRET` |

### Permissions

| Permission | Access | Why |
|---|---|---|
| Repository · **Contents** | Read | Fetch source files of changed contracts |
| Repository · **Checks** | Read & Write | Create and update check-runs |
| Repository · **Pull requests** | Read & Write | Post PR comments |
| Repository · **Metadata** | Read (mandatory) | Resolve default branch, etc. |

### Subscribe to events

- `installation`
- `installation_repositories`
- `push`
- `pull_request`
- `check_run` (for "Re-run" support)

### Where can this GitHub App be installed?

Choose **"Any account"** if you want to offer Forensiq as a public service.
Choose **"Only on this account"** for a private deployment.

Submit the form.

## 2. Generate a private key

After creating the App, scroll down on the App settings page to the **Private keys** section and click **Generate a private key**. GitHub downloads a `.pem` file.

The key is RSA-2048 and is used to sign App-level JWTs (10-minute expiry) which are then exchanged for installation tokens (1-hour expiry).

## 3. Configure the backend

Add to your `.env`:

```env
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
GITHUB_APP_WEBHOOK_SECRET=<the secret you set in step 1>
PUBLIC_URL=https://forensiq.example.com
```

For containers/PaaS that don't like multiline env vars, base64-encode the PEM and the loader handles both:

```bash
GITHUB_APP_PRIVATE_KEY=$(base64 -i forensiq.private-key.pem)
```

## 4. Test the webhook

GitHub sends a `ping` event when the App is first registered. Check your worker logs:

```
[gh-app] sig verify failed (delivery=abc-123 event=ping)
```

means the secret is wrong. Fix and click **Redeliver** on the App's **Advanced** tab in GitHub.

```
{ "ok": true, "message": "pong" }
```

means you're good.

## 5. Install on a test repo

From the App's public page (`https://github.com/apps/your-app-slug`), click **Install**. Choose a repo with at least one `.sol` file. GitHub fires `installation.created` → Forensiq records the installation.

Make a commit that modifies a `.sol` file and push. You should see:

1. A "Forensiq audit · in progress" check on the commit within ~5 seconds
2. Within 1-3 minutes (depending on whether Echidna is enabled), the check completes with the score, findings count, and a link to the full report
3. If the commit was on a PR, a comment appears with the same content

## Troubleshooting

**Check run never appears.** The App might not have `checks: write` permission, or the installation might not include the repo that was pushed to. Check the App settings → Installations → your install → Permissions and configure.

**HMAC verification fails.** Most common cause: the webhook secret in `.env` doesn't match the one in the App's settings. Note the `Redeliver` button in the App's `Advanced` tab — it's invaluable for debugging without making new commits.

**Annotations don't show on the PR diff.** GitHub only shows annotations for lines that are part of the PR's diff. Findings on unchanged lines appear in the check summary but not as inline comments. This is a GitHub limitation, not a Forensiq one.

**"installation token request failed".** Make sure the PEM is the *raw* contents of the file (including header/footer lines). Wrap it in double-quotes in `.env` to preserve newlines, OR base64-encode it.

## Operational notes

- **Token caching** is in-memory per worker process. For multi-instance worker deployments, consider moving the cache to Redis (~50 lines of additional code in `src/github/auth.ts`).
- **Rate limits**: GitHub allows 5,000 requests/hour per installation. Each audit run uses ~3 requests (create check-run, complete check-run, post PR comment). 1,600 audits/hour ceiling per installed user.
- **Suspended installations** appear with `suspended: true`. The webhook handler refuses to mint tokens for them, so events are silently dropped. Users re-enable from their App settings.
