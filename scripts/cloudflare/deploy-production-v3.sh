#!/usr/bin/env bash
set -euo pipefail

WRANGLER_VERSION="${WRANGLER_VERSION:-4.141.0}"
ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-ac1ca1b50d09c7a4cb81274d2aa1e78f}"
WORKER_NAME="ordax-control-plane-v3"
CONTROL_PLANE_URL="https://ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$ROOT/control-plane/cloudflare/wrangler.toml"

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
export CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID"

# Routine production deploys must not provision or mutate bound infrastructure.
# D1/R2/DO bindings are declared in the canonical Wrangler config and existing
# Worker secrets are intentionally preserved by Wrangler.
npx --yes "wrangler@${WRANGLER_VERSION}" deploy --config "$CONFIG"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "control_plane_url=${CONTROL_PLANE_URL}" >> "$GITHUB_OUTPUT"
fi

echo "ORDAX_CONTROL_PLANE_DEPLOY=READY"
echo "WORKER=${WORKER_NAME}"
echo "CONTROL_PLANE_URL=${CONTROL_PLANE_URL}"
