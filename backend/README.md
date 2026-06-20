# Forensiq

**Multi-engine smart contract audit platform with property-based fuzzing, continuous-audit webhooks, and a public report registry.**

Six independent open-source analyzers (Slither, Aderyn, Mythril, Semgrep, Solhint, Echidna) run against the same source. Findings are clustered via SWC-based consensus. A single tool flagging an issue is a *hint*. Three tools flagging the same issue at the same line is *signal*. Forensiq makes that distinction the centerpiece of the report.

## What's new

- **Echidna integration** — property-based fuzzing with auto-generated harness for ERC20/ERC721/Ownable patterns. Property-violation counterexamples are treated as *proofs* in the consensus engine (single-tool, high-confidence).
- **Continuous-audit webhooks** — subscribe a GitHub repo; every push triggers a scoped audit of changed .sol files; results posted via email and/or Slack with score delta vs. previous run.
- **Public report registry** — opt-in publishing; leaderboard with filters (chain, score, severity); per-contract history; full-text search.

## Engines

| Tool | Paradigm | License | Role |
|---|---|---|---|
| [Slither](https://github.com/crytic/slither) 0.10.4 | AST static | AGPL-3.0 | Primary, 90+ detectors |
| [Aderyn](https://github.com/Cyfrin/aderyn) 0.5.5 | AST static (Rust) | MIT | Fast secondary |
| [Mythril](https://github.com/ConsenSys/mythril) 0.24.8 | Symbolic execution | MIT | Deep logic bugs |
| [Semgrep](https://semgrep.dev) 1.85 + smart-contracts | Pattern match | LGPL | Custom rules |
| [Solhint](https://github.com/protofire/solhint) 5.0.5 | Linter | MIT | Style + best-practice |
| [Echidna](https://github.com/crytic/echidna) 2.2.4 | Property fuzzing | AGPL-3.0 | Invariant violations (opt-in) |

All run in isolated Docker containers with `--network none`, `--read-only`, memory caps, timeouts.

## How Echidna fits

Static tools (Slither, Aderyn) tell you what's *suspicious*. Symbolic execution (Mythril) tells you what's *reachable*. Fuzzing (Echidna) gives you a *concrete sequence of calls* that breaks an invariant — a counterexample, not a heuristic.

Because Echidna findings are proofs:
- They're treated as **high-confidence** even when single-tool (special-cased in `consensus/engine.ts`)
- Score penalty uses **2-tool multiplier (1.0×) even for single-tool** Echidna findings
- They're ranked first in the report ordering

**Harness generation** is the hard part of automating Echidna. `src/fuzz/harness.ts` parses the target, detects ERC20/ERC721/Ownable/Pausable patterns, and generates universal + pattern-specific invariants. For an ERC20 it emits:

```solidity
function echidna_total_supply_equals_balance_sum() public view returns (bool) {
  uint256 sum = MyToken(target).balanceOf(ACCT_A)
              + MyToken(target).balanceOf(ACCT_B)
              + MyToken(target).balanceOf(ACCT_C)
              + MyToken(target).balanceOf(address(this));
  return sum <= MyToken(target).totalSupply();
}
function echidna_owner_not_zero() public view returns (bool) { ... }
function echidna_totalMinted_monotonic() public returns (bool) { ... }
```

Plus fuzz entry points wrapping each public function with `try/catch` so Echidna can explore call sequences.

Default campaign: 50k calls, 5-minute timeout. Opt-in via `enableFuzzing: true` on the audit submission.

## GitHub App (recommended)

The Forensiq GitHub App gives you the full experience: red ✗ / green ✓ check-runs on every commit, PR comments with findings, one-click install instead of pasting webhook secrets.

After registering the App (see `docs/github-app.md`) and setting `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, and `GITHUB_APP_WEBHOOK_SECRET`, point the App's webhook at `${PUBLIC_URL}/api/gh/app`. The handler covers:

- `installation` / `installation_repositories` — records and tracks installs
- `push` — opens a pending check-run, queues audits for changed `.sol` files, completes the check-run with findings when done
- `pull_request` (opened, synchronize, reopened) — same flow scoped to the PR's diff, plus a magic-marker comment that updates in place rather than spamming the PR
- `check_run` rerequested — re-runs the audit

JWT signing uses RS256 against the App's private key (cached in memory). Installation tokens are cached per installation ID with a 5-minute safety margin before expiry.

The legacy per-project webhook (`/api/webhooks/github`) still works for users who don't want to install the App — they get email + Slack notifications but no GitHub UI integration.

## Frontend

A vanilla-JS SPA lives in `../frontend/`. No build step; serve it with any static server (or open `index.html` directly with `?api=http://localhost:3000`).

Six routes:
- `#/scan` — submit audits (paste / address / GitHub), live progress console, Echidna toggle
- `#/report/:id` — full report with animated score ring, AI brief panel, expandable findings showing consensus tool-count badges, share/PDF/publish actions
- `#/registry` — public leaderboard with chain/score/sort filters, full-text search
- `#/watch` — manage continuous-audit projects with GitHub setup modal
- `#/runs/:id` — per-project run history with score deltas
- `#/install` — GitHub App install CTA

Styling commits to the forensic console aesthetic: JetBrains Mono + Fraunces serif display, amber + red accents on a near-black surface, subtle grid background. Tool-count badges in findings make the consensus signal visually obvious — single-tool findings render muted gray, multi-tool consensus findings glow green.

The frontend uses HttpOnly session cookies issued after GitHub OAuth login. Anonymous browsing is allowed for read-only views (scan submission, registry, install page). Watch projects and run history require authentication. See **Authentication** below.

## Quick start (full stack)

```bash
# 1. Build tool images (one-time, ~20min)
cd backend
docker compose --profile build-tools build

# 2. Configure
cp .env.example .env
# Fill in keys

# 3. Start backend
docker compose up -d

# 4. Serve frontend
cd ../frontend
python3 -m http.server 8080
# Open http://localhost:8080?api=http://localhost:3000
```

## Webhook continuous-audit mode

1. User creates a watched project: `POST /api/watch { repo, branch, pathFilter, notifyEmail, notifySlack, minSeverity }`
2. Forensiq returns a webhook URL + cryptographically random secret
3. User configures the GitHub webhook
4. On each push:
   - HMAC SHA-256 verified with timing-safe comparison
   - Changed .sol files matching pathFilter are extracted (capped at 10/push)
   - Audits enqueued; results posted to email + Slack with score delta

Notifications include the score delta vs. the previous run on the same project. So a PR that regresses the score by -8 points is immediately visible.

## Public registry

Reports are private by default. After an audit completes, the owner can:

```
POST /api/registry/publish/:reportId
{ "tags": ["defi", "lending"], "verifiedSource": true }
```

The entry then appears in:
- `GET /api/registry?chain=ethereum&minScore=80&sort=score_desc` — leaderboard
- `GET /api/registry/contract/ethereum/0xabc...` — current + history for one contract
- `GET /api/registry/chains` — aggregate per-chain stats

**Supersession rule**: publishing a new entry for an existing `(chain, address)` marks the prior entry as superseded. The leaderboard shows the current entry; the history view shows all. Owners can't delete published reports — once an audit firm puts something in writing, they own it. Same principle here.

Full-text search uses Postgres `tsvector` indexes on contract name, repo, and address.

## Architecture

```
┌────────────┐          ┌──────────────┐
│  Frontend  │          │   GitHub     │
└─────┬──────┘          └──────┬───────┘
      │ POST /api/audits       │ push webhook
      │                        │
      ▼                        ▼
┌──────────────────────────────────────┐
│                API                   │
│  - audits (sync submit)              │
│  - watch (manage subscriptions)      │
│  - registry (publish + browse)       │
│  - webhooks/github (HMAC verified)   │
└──────────────┬───────────────────────┘
               │
               ▼
        ┌──────────┐ BullMQ
        │  Redis   │
        └────┬─────┘
             │
             ▼
       ┌─────────────┐
       │   Worker    │── parallel
       └─────┬───────┘
             │
   ┌──┬──┬──┼──┬──┬──┐
   ▼  ▼  ▼  ▼  ▼  ▼  ▼
  [Slither][Mythril][Aderyn][Semgrep][Solhint][Echidna]
   │  │  │  │  │  │
   └──┴──┼──┴──┴──┘
         ▼
  ┌─────────────────┐
  │ Consensus Engine│ SWC clustering, severity reconciliation,
  └────────┬────────┘ tool-weighted scoring
           │
           ▼
  ┌─────────────────┐
  │  Persistence    │ Postgres: reports, watched_*, registry_entries
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Notify dispatcher│ email + slack on watched runs
  └─────────────────┘
```

## API reference

### Audits

- `POST /api/audits` — submit, returns job id. Body: `{ source: {paste|address|github}, tools?, enableFuzzing? }`
- `GET /api/audits/:id` — poll status / fetch completed report
- `GET /api/audits/:id/pdf` — download PDF report

### Watched projects (continuous audit)

- `POST /api/watch` — subscribe a repo. Returns webhook URL + secret with setup instructions
- `GET /api/watch` — list your projects
- `GET /api/watch/:id` — details
- `DELETE /api/watch/:id` — unsubscribe
- `GET /api/watch/:id/runs` — recent runs
- `POST /api/webhooks/github` — GitHub webhook endpoint (HMAC verified)

### Public registry

- `POST /api/registry/publish/:reportId` — publish a report (auth required). Body: `{ tags?, verifiedSource? }`
- `GET /api/registry?chain=&minScore=&sort=&search=` — leaderboard
- `GET /api/registry/chains` — per-chain aggregate stats
- `GET /api/registry/contract/:chain/:address` — current + history

## Consensus & scoring (updated)

Same as before, with one addition: **Echidna findings get full weight even single-tool** because a counterexample is a proof, not a heuristic.

```
penalty = Σ base_weight[severity] × tool_multiplier[toolCount]
where tool_multiplier:
  echidna single-tool: 1.0 (proof, not heuristic)
  1 tool:  0.5
  2 tools: 1.0
  3 tools: 1.5
  4+:      2.0
```

## API example

```bash
# Submit an audit with property-based fuzzing enabled
curl -X POST http://localhost:3000/api/audits \
  -H "Content-Type: application/json" \
  -d '{
    "source": {"type": "github", "repo": "myorg/contracts", "path": "src/Vault.sol"},
    "enableFuzzing": true
  }'
```

## Authentication

Forensiq uses **GitHub OAuth** for login. Sessions are HttpOnly cookies signed with `SESSION_SECRET` (HS256 JWT, 7-day TTL). Anonymous browsing works for read-only views (scan, registry, install). Watch projects and publish require login.

Setup:

1. Register an OAuth App at https://github.com/settings/applications/new — this is **separate** from the GitHub App used for repo integration.
2. Set the callback URL to `${PUBLIC_URL}/api/auth/github/callback`.
3. Set env vars:

```env
GITHUB_OAUTH_CLIENT_ID=Iv1.xxxxx
GITHUB_OAUTH_CLIENT_SECRET=...
SESSION_SECRET=$(openssl rand -hex 32)
PUBLIC_URL=https://forensiq.example.com
FRONTEND_URL=https://forensiq.example.com   # if frontend is on a different origin
```

OAuth scope is `read:user user:email` only — no repo permissions needed because the GitHub App handles repo data with its own installation tokens. When a user logs in for the first time, any pending GitHub App installations under their GitHub login are automatically claimed.

See `docs/auth.md` for the full setup walkthrough.

## License

Forensiq is **AGPL-3.0-or-later**. See `LICENSE` and `NOTICE`.

If you host Forensiq as a service, AGPL Section 13 requires you to make the corresponding source code available to users of that service. The default footer includes a "Source" link pointing to the upstream repository; if you modify Forensiq, point that link at your modified source.

The four MIT/LGPL engines (Aderyn, Mythril, Semgrep, Solhint) and the two AGPL engines (Slither, Echidna) are all license-compatible with Forensiq's AGPL distribution. See `NOTICE` for the full attribution table.

## Production checklist

- [x] Real auth (GitHub OAuth + signed session cookies)
- [x] AGPL compliance with source-availability footer link
- [x] Redis-backed rate limiter (sliding-window, atomic Lua, fail-open)
- [x] Prometheus metrics at /metrics
- [x] S3 archival of raw outputs and PDF reports (worker-side, IRSA)
- [x] Kustomize manifests with HPA + KEDA + PodDisruptionBudget + NetworkPolicy
- [x] Terraform for the full AWS stack (EKS + RDS + ElastiCache + S3 + ECR)
- [x] CI pipeline with OIDC, immutable ECR tags, multi-arch builds, Trivy scan
- [x] Docker base images pinnable by digest (`scripts/pin-images.sh`)
- [ ] Sentry error reporting integration
- [ ] Run Forensiq on Forensiq before public launch (eat your own dogfood)
- [ ] Disaster recovery drill: practice the restore-from-backup procedure
- [ ] Rotate `SESSION_SECRET` periodically (use JWT `kid` for overlap)

## Tests

```bash
npm test     # 36 tests across 4 files
```

All trust-critical paths covered:
- Consensus clustering across tools (9 tests)
- Echidna harness generation for ERC20/Ownable (3 tests)
- GitHub HMAC verification including tamper resistance (6 tests)
- Echidna single-tool weighting (2 tests)
- OAuth state signing + tamper detection (7 tests)
- Session JWT rejection of wrong-secret, wrong-issuer, expired, alg:none (6 tests)
- SigV4 signing primitives for S3 archival (3 tests)
