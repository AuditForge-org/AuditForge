#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Entrypoint shim for the Forensiq image.
#
# The worker needs to reach the host Docker socket (mounted at
# /var/run/docker.sock) as a non-root user. The socket is owned by some
# `docker` GID on the host that we can't know at build time. This script:
#
#   1. If the socket is present, find its group owner GID
#   2. Ensure a group with that GID exists inside the container and add
#      the forensiq user to it
#   3. Drop from root to forensiq and exec the real command
#
# The API container has no socket mounted, so step 1-2 are skipped and it
# just drops to forensiq immediately.
#
# We run as root only for this brief setup, then never again.

set -e

SOCKET=/var/run/docker.sock

if [ -S "$SOCKET" ]; then
  # GID that owns the socket on the host
  SOCK_GID=$(stat -c '%g' "$SOCKET")
  # Is there already a group with this GID?
  if ! getent group "$SOCK_GID" >/dev/null 2>&1; then
    groupadd -g "$SOCK_GID" dockerhost
    GROUP_NAME=dockerhost
  else
    GROUP_NAME=$(getent group "$SOCK_GID" | cut -d: -f1)
  fi
  # Add forensiq to that group if not already a member
  if ! id -nG forensiq | tr ' ' '\n' | grep -qx "$GROUP_NAME"; then
    usermod -aG "$GROUP_NAME" forensiq
  fi
fi

# Drop to the unprivileged user and run. `setpriv` is in util-linux
# (present in the base image); falls back to `su` if not.
if command -v setpriv >/dev/null 2>&1; then
  # Re-resolve forensiq's full group list after the usermod above
  exec setpriv --reuid forensiq --regid forensiq --init-groups "$@"
else
  exec su -s /bin/sh forensiq -c "exec $*"
fi
