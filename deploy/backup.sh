#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FORENSIQ — Postgres backup.
#
# Dumps the database to a timestamped gzip, keeps the last N locally, and
# (optionally) ships to an S3-compatible bucket. Run nightly via cron:
#
#   crontab -e
#   0 3 * * *  /path/to/forensiq/deploy/backup.sh >> /var/log/forensiq-backup.log 2>&1
#
# Restore from a backup:
#   gunzip -c backups/forensiq-2026-05-22.sql.gz | \
#     docker compose -f docker-compose.prod.yml exec -T postgres \
#     psql -U forensiq -d forensiq

set -euo pipefail

# ─── Config ─────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${FORENSIQ_BACKUP_DIR:-$REPO_DIR/backups}"
KEEP_DAYS="${FORENSIQ_BACKUP_KEEP_DAYS:-14}"
COMPOSE="docker compose -f $REPO_DIR/docker-compose.prod.yml"

# Optional off-site: set these env vars to ship to S3-compatible storage.
# Works with Backblaze B2, Wasabi, MinIO, AWS S3 — anything the aws CLI
# or rclone speaks. We use rclone if present, else skip.
#   FORENSIQ_BACKUP_RCLONE_REMOTE=b2:my-bucket/forensiq

mkdir -p "$BACKUP_DIR"
STAMP=$(date +%Y-%m-%d_%H%M%S)
OUT="$BACKUP_DIR/forensiq-$STAMP.sql.gz"

echo "[$(date)] Starting backup → $OUT"

# ─── Dump ───────────────────────────────────────────────────────────────
# pg_dump inside the container, piped out and gzipped on the host.
$COMPOSE exec -T postgres pg_dump -U forensiq -d forensiq --no-owner --clean --if-exists \
  | gzip -9 > "$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
echo "[$(date)] Dump complete: $SIZE"

# Sanity check — a valid gzip with non-trivial size
if [ "$(stat -c%s "$OUT")" -lt 1000 ]; then
  echo "[$(date)] WARNING: backup is suspiciously small. Check the database."
  exit 1
fi

# ─── Off-site (optional) ─────────────────────────────────────────────────
if [ -n "${FORENSIQ_BACKUP_RCLONE_REMOTE:-}" ]; then
  if command -v rclone >/dev/null 2>&1; then
    echo "[$(date)] Shipping to $FORENSIQ_BACKUP_RCLONE_REMOTE"
    rclone copy "$OUT" "$FORENSIQ_BACKUP_RCLONE_REMOTE/"
    echo "[$(date)] Off-site copy done"
  else
    echo "[$(date)] rclone not installed; skipping off-site copy"
  fi
fi

# ─── Prune old local backups ──────────────────────────────────────────────
echo "[$(date)] Pruning backups older than $KEEP_DAYS days"
find "$BACKUP_DIR" -name 'forensiq-*.sql.gz' -mtime +"$KEEP_DAYS" -delete

echo "[$(date)] Backup finished. Local backups:"
ls -lh "$BACKUP_DIR"/forensiq-*.sql.gz | tail -5
