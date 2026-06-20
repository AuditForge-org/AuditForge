#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AUDIT FORGE — issue the Let's Encrypt cert for the public domain automatically,
# as soon as DNS points it at this box. Runs from cron every few minutes and is
# a cheap no-op until (a) the domain resolves here and (b) the cert is issued,
# after which it removes itself from the crontab.
#
#   */10 * * * *  /srv/dapp/forensiq/deploy/certbot-when-ready.sh
#
# certbot reuses the box's existing ACME account (already used for cterminal.xyz,
# epow.io and audit.axolittles.io), so no email/registration prompt.

set -uo pipefail

DOMAIN=auditforge.org
WWW=www.auditforge.org
TARGET_IP=65.21.133.18
LOG=/srv/dapp/forensiq/certbot-when-ready.log
exec >>"$LOG" 2>&1

self_remove() {
  ( crontab -l 2>/dev/null | grep -v 'certbot-when-ready.sh' ) | crontab - || true
}

# Already issued? Stop running.
if sudo certbot certificates 2>/dev/null | grep -q "Certificate Name: $DOMAIN"; then
  echo "[$(date)] cert for $DOMAIN already present — removing self from crontab."
  self_remove
  exit 0
fi

# Require the A record to be visible from BOTH major public resolvers before
# attempting certbot. LE validates from multiple network perspectives, and
# firing certbot before the record has propagated globally just burns LE's
# "5 failed validations per hour" budget for the hostname.
resolves() { dig +short "$1" A "@$2" 2>/dev/null | grep -qx "$TARGET_IP"; }
if ! { resolves "$DOMAIN" 1.1.1.1 && resolves "$DOMAIN" 8.8.8.8; }; then
  echo "[$(date)] $DOMAIN not globally resolved to $TARGET_IP yet (1.1.1.1='$(dig +short "$DOMAIN" A @1.1.1.1 | tr '\n' ' ')' 8.8.8.8='$(dig +short "$DOMAIN" A @8.8.8.8 | tr '\n' ' ')'). Waiting."
  exit 0
fi

# Include www only if it also points here, so a missing www record can't fail
# the whole certificate request.
DOMS=(-d "$DOMAIN")
if resolves "$WWW" 1.1.1.1 && resolves "$WWW" 8.8.8.8; then
  DOMS+=(-d "$WWW")
else
  echo "[$(date)] $WWW not pointing here yet — issuing apex-only (can expand later)."
fi

echo "[$(date)] $DOMAIN globally -> $TARGET_IP. Running: certbot --nginx ${DOMS[*]}"
sudo certbot --nginx "${DOMS[@]}" --non-interactive --agree-tos --redirect --keep-until-expiring
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "[$(date)] certbot SUCCESS — $DOMAIN is now on HTTPS. Removing self from crontab."
  self_remove
else
  echo "[$(date)] certbot failed (rc=$rc). Will retry on the next run."
fi
