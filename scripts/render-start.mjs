#!/usr/bin/env sh
set -e

# Render sets PORT automatically. Fallback only for local runs.
: "${PORT:=10000}"

exec node dist/index.js gateway \
  --allow-unconfigured \
  --bind lan \
  --port "$PORT"
