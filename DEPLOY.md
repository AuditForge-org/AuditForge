<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Forensiq — VPS test deployment

Deploy Forensiq to a single Ubuntu server for testing. This is the fast path: one compose file, one deploy script, one reverse proxy. No Kubernetes, no Terraform.

## Before you start

You need:

- An **Ubuntu 22.04 or 24.04** VPS — minimum 4 vCPU / 8 GB RAM (Mythril and Echidna are hungry; on 8 GB set `WORKER_CONCURRENCY=1` and add swap).
- A **domain name** with an A-record you can point at the server.
- An **Anthropic API key** (for the AI brief; audits run without it but skip the summary).
- ~30 minutes (most of it waiting for the six engine images to build).

The GitHub OAuth App and GitHub App are **optional for first testing** — paste-mode audits work without any GitHub setup. Add them when you want login and PR integration (see `docs/auth.md` and `docs/github-app.md`).

## Step 1 — Server prep

SSH in as a sudo user, then:

```bash
# Firewall
sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable

# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker   # or log out/in so the group takes effect

# Swap (important on 8 GB boxes so a heavy audit can't OOM the host)
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Step 2 — Get the code and configure

```bash
git clone <your-fork-url> forensiq
cd forensiq

cp .env.production.example .env
nano .env
```

Fill in at minimum:

```ini
PUBLIC_URL=https://forensiq.yourdomain.com
FRONTEND_URL=https://forensiq.yourdomain.com
POSTGRES_PASSWORD=<openssl rand -hex 24>
SESSION_SECRET=<openssl rand -hex 32>
ANTHROPIC_API_KEY=sk-ant-...
WORKER_CONCURRENCY=1          # for an 8 GB box; raise on bigger servers
```

Then lock it down: `chmod 600 .env`

## Step 3 — Deploy

```bash
./deploy.sh
```

This builds the six engine images (~20 min the first time), builds the app, brings the stack up, waits for health, and verifies the schema. Subsequent app-only redeploys: `./deploy.sh --skip-engines`.

When it finishes, the API is listening on `127.0.0.1:3000` (localhost only — the reverse proxy handles the public side).

## Step 4 — TLS with Caddy

The Caddyfile serves the static frontend directly and proxies `/api/*` to the backend, so everything lives on one domain (no CORS headaches).

```bash
sudo apt install -y caddy
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
# Set your domain:
sudo sed -i 's/forensiq.example.com/forensiq.yourdomain.com/' /etc/caddy/Caddyfile
# Set the frontend path to where you cloned the repo (the default assumes
# /home/forensiq/forensiq). If you cloned elsewhere, edit the `root` line:
sudo nano /etc/caddy/Caddyfile   # check the `root * .../frontend` line
sudo systemctl reload caddy
```

Caddy needs read access to the `frontend/` directory. If you cloned under a different user's home, either move the repo somewhere Caddy can read (e.g. `/srv/forensiq`) or adjust permissions.

Point your DNS A-record at the server. Within a minute Caddy fetches a Let's Encrypt cert automatically. Visit `https://forensiq.yourdomain.com`.

## Step 5 — Validate (the important part)

This is the step that tells you whether the audit engines actually work end-to-end — the unit tests only cover mocked output.

```bash
./test/smoke-test.sh
```

It submits four known contracts (reentrancy, tx.origin, delegatecall, and a clean one) and checks the findings match expectations. **Expect to do some debugging here** — real tool output formats can differ from what the normalizers anticipate, and you may need to adjust a normalizer. If a test fails:

```bash
docker compose -f docker-compose.prod.yml logs worker | tail -100
```

The worker logs show each `docker run` invocation and its raw output, which is exactly what you need to fix a normalizer mismatch.

## Step 6 — Backups

```bash
crontab -e
# add this line (adjust the path):
0 3 * * *  /home/youruser/forensiq/deploy/backup.sh >> /var/log/forensiq-backup.log 2>&1
```

For off-site copies, install `rclone`, configure a remote, and set `FORENSIQ_BACKUP_RCLONE_REMOTE=remote:bucket/forensiq` in the cron environment.

## Day-to-day operations

```bash
# Tail logs
docker compose -f docker-compose.prod.yml logs -f api worker

# Status
docker compose -f docker-compose.prod.yml ps

# Restart just the worker (e.g. after tuning concurrency)
docker compose -f docker-compose.prod.yml restart worker

# Update after pulling new code
git pull && ./deploy.sh --update

# Stop everything (data persists in volumes)
docker compose -f docker-compose.prod.yml down

# Restore from a backup
gunzip -c backups/forensiq-DATE.sql.gz | \
  docker compose -f docker-compose.prod.yml exec -T postgres psql -U forensiq -d forensiq
```

## Known limitations for this test setup

- **Single host = single point of failure.** Fine for testing; for production move Postgres to a managed service.
- **The clean-contract test imports OpenZeppelin.** If your engine images can't resolve npm imports during analysis, that test may error — that's an import-resolution limitation, not a Forensiq bug. The three vulnerable contracts are self-contained and are the real signal.
- **No billing / quota controls.** Anyone who can reach the instance can spend your Anthropic budget and CPU. Keep it behind auth or a firewall until you add quotas.
- **AGPL:** the frontend footer "Source code" link must point at your actual deployed source. Update it before exposing the instance publicly.

## Troubleshooting

**`deploy.sh` says engine images not found** — you passed `--skip-engines` on a first run. Run plain `./deploy.sh`.

**Worker can't reach Docker** — confirm the socket is mounted: `docker compose -f docker-compose.prod.yml exec worker docker ps` should list containers. If permission denied, the entrypoint GID-alignment didn't catch your host's docker group; check `stat -c '%g' /var/run/docker.sock` and ensure the worker container can read it.

**Audits stuck in "queued"** — the worker isn't consuming. Check `docker compose -f docker-compose.prod.yml logs worker`. Common cause: Redis connection or the worker crashed on startup.

**Out of memory during audits** — lower `WORKER_CONCURRENCY`, confirm swap is on (`swapon --show`), or size up the VPS.
