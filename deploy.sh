#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FORENSIQ — one-shot VPS deploy.
#
# Run this from the repo root on a fresh Ubuntu 22.04/24.04 server that
# already has Docker installed (the script checks). It:
#
#   1. Validates .env exists and has the required secrets
#   2. Builds the six engine images (one-time, ~20 min)
#   3. Builds the app image
#   4. Brings up the stack
#   5. Waits for health and prints next steps
#
# Usage:
#   cp .env.production.example .env
#   nano .env                       # fill in secrets
#   ./deploy.sh                     # full deploy
#   ./deploy.sh --skip-engines      # redeploy app only (engines already built)
#   ./deploy.sh --update            # pull code, rebuild app, rolling restart

set -euo pipefail

COMPOSE="docker compose -f docker-compose.prod.yml"
SKIP_ENGINES=0
UPDATE=0

for arg in "$@"; do
  case "$arg" in
    --skip-engines) SKIP_ENGINES=1 ;;
    --update) UPDATE=1; SKIP_ENGINES=1 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# ─── Colours ───────────────────────────────────────────────────────────
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }
step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }

# ─── Preflight ──────────────────────────────────────────────────────────
step "Preflight checks"

if ! command -v docker >/dev/null 2>&1; then
  red "Docker not found. Install it first:"
  echo "  curl -fsSL https://get.docker.com | sh"
  exit 1
fi
green "✓ docker present: $(docker --version)"

if ! docker compose version >/dev/null 2>&1; then
  red "docker compose v2 not found. Install the compose plugin."
  exit 1
fi
green "✓ docker compose present"

if [ ! -f .env ]; then
  red ".env not found."
  echo "  cp .env.production.example .env && nano .env"
  exit 1
fi

# Verify the must-have secrets are non-empty
missing=0
check_env() {
  local key="$1"
  local val
  val=$(grep -E "^${key}=" .env | head -1 | cut -d= -f2-)
  if [ -z "$val" ]; then
    red "✗ $key is empty in .env"
    missing=1
  else
    green "✓ $key set"
  fi
}
check_env POSTGRES_PASSWORD
check_env SESSION_SECRET
check_env PUBLIC_URL
# ANTHROPIC_API_KEY is intentionally optional for this deployment: every
# analysis engine still runs, only the AI auditor brief is skipped, and the
# worker handles a missing/empty key gracefully (try/catch around the brief).
if [ -z "$(grep -E '^ANTHROPIC_API_KEY=' .env | head -1 | cut -d= -f2-)" ]; then
  yellow "⚠ ANTHROPIC_API_KEY empty — deploying without the AI brief (engines still run)."
fi

if [ "$missing" -eq 1 ]; then
  red "\nFill in the missing secrets in .env and re-run."
  echo "Generate secrets with:"
  echo "  openssl rand -hex 24   # POSTGRES_PASSWORD"
  echo "  openssl rand -hex 32   # SESSION_SECRET"
  exit 1
fi

# Available memory warning
total_mb=$(free -m | awk '/^Mem:/{print $2}')
if [ "$total_mb" -lt 7000 ]; then
  yellow "⚠ Only ${total_mb}MB RAM detected. Mythril + Echidna are memory-hungry."
  yellow "  Set WORKER_CONCURRENCY=1 in .env and ensure swap is configured:"
  yellow "    sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile"
  yellow "    sudo mkswap /swapfile && sudo swapon /swapfile"
fi

# ─── Update mode ────────────────────────────────────────────────────────
if [ "$UPDATE" -eq 1 ]; then
  step "Update mode: rebuild app and rolling restart"
  $COMPOSE build api
  $COMPOSE up -d --no-deps api worker
  green "✓ Updated. Tailing logs (Ctrl-C to exit):"
  exec $COMPOSE logs -f api worker
fi

# ─── Build engine images ────────────────────────────────────────────────
if [ "$SKIP_ENGINES" -eq 0 ]; then
  step "Building 6 engine images (one-time, grab a coffee — ~20 min)"
  $COMPOSE --profile build-tools build
  green "✓ Engine images built:"
  docker images --format '  {{.Repository}}:{{.Tag}}' | grep '^  forensiq/' || true
else
  yellow "Skipping engine build (--skip-engines)"
  # Sanity: are they actually present?
  if ! docker images --format '{{.Repository}}' | grep -q '^forensiq/slither'; then
    red "Engine images not found but --skip-engines was passed."
    red "Run without --skip-engines for the first deploy."
    exit 1
  fi
fi

# ─── Build app image ──────────────────────────────────────────────────────
step "Building app image"
$COMPOSE build api
green "✓ App image built"

# ─── Bring up the stack ───────────────────────────────────────────────────
step "Starting the stack"
$COMPOSE up -d

# ─── Wait for health ──────────────────────────────────────────────────────
step "Waiting for the API to come up"
ok=0
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
  printf '.'
done
echo

if [ "$ok" -eq 1 ]; then
  green "✓ API is healthy at http://127.0.0.1:3000/api/health"
else
  red "✗ API did not become healthy in 60s. Check logs:"
  echo "  $COMPOSE logs api"
  exit 1
fi

# ─── Verify DB schema ─────────────────────────────────────────────────────
step "Verifying database schema"
tables=$($COMPOSE exec -T postgres psql -U forensiq -d forensiq -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null || echo 0)
if [ "$tables" -ge 6 ]; then
  green "✓ Database has $tables tables"
else
  yellow "⚠ Only $tables tables found. init.sql may not have run. Check:"
  echo "  $COMPOSE exec postgres psql -U forensiq -d forensiq -c '\\dt'"
fi

# ─── Done ─────────────────────────────────────────────────────────────────
step "Deploy complete"
cat <<'EOF'

  The stack is running, listening on 127.0.0.1:3000 (localhost only).

  NEXT STEPS:

  1. Put a reverse proxy in front for TLS. Caddy is easiest:
       sudo apt install caddy
       sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
       # edit the domain in /etc/caddy/Caddyfile
       sudo systemctl reload caddy

  2. Point your DNS A-record at this server's IP.

  3. Smoke-test a real audit:
       ./test/smoke-test.sh

  4. Set up nightly backups:
       crontab -e
       # add:  0 3 * * *  /path/to/forensiq/deploy/backup.sh

  USEFUL COMMANDS:
    docker compose -f docker-compose.prod.yml logs -f api worker
    docker compose -f docker-compose.prod.yml ps
    docker compose -f docker-compose.prod.yml restart worker
    ./deploy.sh --update      # after git pull

EOF
