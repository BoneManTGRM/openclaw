# Dockerfile
# Updates vs your current version
# - Installs curl and ca-certificates (bun installer and many package installs need them)
# - Runs bun install as the node user so ownership is correct and bun is usable at runtime
# - Keeps pnpm via corepack, and preserves good layer caching
# - Leaves your CMD the same

FROM node:22-bookworm

WORKDIR /app

# System packages
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
RUN set -eux; \
    mkdir -p /home/node/.bun; \
    chown -R node:node /home/node

USER node
RUN curl -fsSL https://bun.sh/install | bash
USER root

# Copy only dependency manifests first (better Docker cache)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY ui/package.json ./ui/package.json
COPY patches ./patches
COPY scripts ./scripts

# Install deps
RUN pnpm install --frozen-lockfile

# Copy the rest of the repo
COPY . .

# Build
RUN OPENCLAW_A2UI_SKIP_MISSING=1 pnpm build
ENV OPENCLAW_PREFER_PNPM=1
RUN pnpm ui:build

ENV NODE_ENV=production

# Ownership and runtime user
RUN chown -R node:node /app /home/node
USER node

CMD ["node", "scripts/railway-start.mjs"]
