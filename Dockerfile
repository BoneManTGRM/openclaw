# Dockerfile
# Railway-friendly OpenClaw build (volume-safe)
# - Uses /home/node/.openclaw for state + workspace (best for Railway volume mount)
# - Installs curl + ca-certificates (bun installer + registries need these)
# - Installs pnpm via corepack and pins PNPM_VERSION
# - Installs bun as the node user so it works at runtime (owned by /home/node)
# - Preserves good layer caching (copy manifests first, install deps, then copy rest)
# - Runs as node at runtime

FROM node:22-bookworm

WORKDIR /app

# Optional system packages (and required curl/ca-certs)
ARG OPENCLAW_DOCKER_APT_PACKAGES=""
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      $OPENCLAW_DOCKER_APT_PACKAGES; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Enable corepack and activate pnpm explicitly
ARG PNPM_VERSION=9.15.4
RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate

# Bun install under the node user (so it is owned correctly and works at runtime)
ENV BUN_INSTALL=/home/node/.bun
ENV PATH="${BUN_INSTALL}/bin:${PATH}"

# IMPORTANT: Put OpenClaw state + workspace under /home/node/.openclaw
# Mount your Railway volume to /home/node/.openclaw
ENV OPENCLAW_STATE_DIR=/home/node/.openclaw
ENV OPENCLAW_WORKSPACE_DIR=/home/node/.openclaw/workspace

RUN set -eux; \
    mkdir -p /home/node/.bun /home/node/.openclaw /home/node/.openclaw/workspace; \
    chown -R node:node /home/node /app

USER node
RUN set -eux; \
    curl -fsSL https://bun.sh/install | bash; \
    bun --version
USER root

# Copy only dependency manifests first (better Docker cache)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY ui/package.json ./ui/package.json
COPY patches ./patches
COPY scripts ./scripts

# Install deps (as root is fine; we fix ownership later)
RUN pnpm install --frozen-lockfile

# Copy the rest of the repo
COPY . .

# Build
RUN OPENCLAW_A2UI_SKIP_MISSING=1 pnpm build
ENV OPENCLAW_PREFER_PNPM=1
RUN pnpm ui:build

ENV NODE_ENV=production

# Ensure runtime can write to state + workspace
RUN set -eux; \
    mkdir -p /home/node/.openclaw /home/node/.openclaw/workspace; \
    chown -R node:node /app /home/node

USER node

CMD ["node", "scripts/railway-start.mjs"]
