# Dockerfile (updated)
# Fixes:
# - Bun was installed under /root, but the container runs as USER node (bun often ends up unusable).
# - Ensures pnpm is actually activated via corepack (some builds fail if pnpm isn’t prepared).
# - Keeps your layer caching good (deps install before copying full repo).
# - Leaves your start command as-is.

FROM node:22-bookworm

WORKDIR /app

# Optional system packages (kept from your original)
ARG OPENCLAW_DOCKER_APT_PACKAGES=""
RUN if [ -n "$OPENCLAW_DOCKER_APT_PACKAGES" ]; then \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $OPENCLAW_DOCKER_APT_PACKAGES && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    fi

# Enable corepack and activate pnpm explicitly
ARG PNPM_VERSION=9.15.4
RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate

# Install bun somewhere the node user can use
ENV BUN_INSTALL=/home/node/.bun
ENV PATH="${BUN_INSTALL}/bin:${PATH}"
RUN curl -fsSL https://bun.sh/install | bash

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
