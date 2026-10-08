#!/usr/bin/env bash
set -euo pipefail

WRANGLER_VERSION="${WRANGLER_VERSION:-4.141.0}"
ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$ROOT/control-plane/cloudflare/wrangler.toml"

# Enforce the exact same fail-closed gate even when invoked outside GitHub Actions.
# This runs before touching Cloudflare APIs or consuming deployment credentials.
python "$ROOT/scripts/cloudflare/check_deploy_readiness.py"
bash "$ROOT/scripts/cloudflare/assert-current-main.sh" "$ROOT"

WORKER_NAME="$(python - "$ROOT/control-plane/cloudflare/production-foundation.json" <<'PY'
import json, sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["worker_name"])
PY
)"

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
export CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID"

cloudflare_api() {
  curl --fail-with-body --silent --show-error \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    "$@"
}

# Resolve the destination URL from the dedicated account at deploy time.
# Routine deploys never create the workers.dev subdomain.
subdomain_json="$(cloudflare_api \
  "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/subdomain")"
WORKERS_SUBDOMAIN="$(printf '%s' "$subdomain_json" | python -c '
import json,sys
data=json.load(sys.stdin)
print((data.get("result") or {}).get("subdomain") or "")
')"
if [[ -z "$WORKERS_SUBDOMAIN" ]]; then
  echo "Dedicated Cloudflare account has no workers.dev subdomain; bootstrap it explicitly before deployment." >&2
  exit 2
fi

# A routine CI Editor token must never bootstrap infrastructure. Refuse to
# publish if the named Worker does not already exist in the dedicated account.
script_json="$(cloudflare_api "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME")"
worker_found="$(printf '%s' "$script_json" | python -c '
import json,sys
r=json.load(sys.stdin)
print("true" if r.get("success") is True and (r.get("result") or {}).get("id") == sys.argv[1] else "false")
' "$WORKER_NAME")"
if [[ "$worker_found" != "true" ]]; then
  echo "Existing Worker identity could not be verified; run the isolated initial bootstrap after cutover" >&2
  exit 4
fi

CONTROL_PLANE_URL="https://$WORKER_NAME.$WORKERS_SUBDOMAIN.workers.dev"

# Routine production deploys must not provision or mutate bound infrastructure.
# All required bindings must already exist and match the canonical production foundation.
npx --yes "wrangler@${WRANGLER_VERSION}" deploy --config "$CONFIG"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "control_plane_url=${CONTROL_PLANE_URL}" >> "$GITHUB_OUTPUT"
fi

echo "ORDAX_CONTROL_PLANE_DEPLOY=READY"
echo "WORKER=${WORKER_NAME}"
echo "CONTROL_PLANE_URL=${CONTROL_PLANE_URL}"
