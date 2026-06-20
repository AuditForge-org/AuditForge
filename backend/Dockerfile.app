# Forensiq backend image
#
# Multi-stage build:
#   - builder: full Node + tsc + dev deps
#   - runtime: slim Node, prod deps only, non-root
#
# Two execution modes via CMD override:
#   - API:    node dist/server.js
#   - Worker: node dist/worker.js
#
# In Kubernetes (ENGINE_RUNTIME=kubernetes) the worker creates Jobs via
# the K8s API and does NOT need the docker CLI. In docker-compose
# (ENGINE_RUNTIME=docker) the docker CLI is required AND the docker
# socket must be mounted (compose handles this). The image includes
# the docker CLI so the same image works in both modes.

# ─── Builder ──────────────────────────────────────────────────────────
FROM node:20-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS builder
# NOTE: replace digest with the real one from `docker pull node:20-bookworm-slim && docker inspect`

WORKDIR /app

# Cache npm install layer
COPY package*.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build && \
    npm prune --omit=dev

# ─── Runtime ──────────────────────────────────────────────────────────
FROM node:20-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

# Docker CLI for ENGINE_RUNTIME=docker. ~25MB extra; acceptable.
# In Kubernetes (prod) the worker does not use this binary.
RUN apt-get update && \
    apt-get install -y --no-install-recommends docker.io tini && \
    rm -rf /var/lib/apt/lists/* && \
    # Non-root user
    groupadd -g 1000 forensiq && \
    useradd -u 1000 -g forensiq -m -d /home/forensiq forensiq

WORKDIR /app

# Copy built artifacts + pruned node_modules
COPY --from=builder --chown=forensiq:forensiq /app/dist ./dist
COPY --from=builder --chown=forensiq:forensiq /app/node_modules ./node_modules
COPY --from=builder --chown=forensiq:forensiq /app/package.json ./package.json

USER forensiq

ENV NODE_ENV=production
ENV NODE_OPTIONS="--enable-source-maps"
EXPOSE 3000

# tini reaps zombie processes (important for the API since express keeps
# the event loop busy and node's PID 1 handling is incomplete)
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/server.js"]
