#!/usr/bin/env bash
# One-time, no-D1 Worker creation in the dedicated OrdaX Cloudflare account.
# Never use the routine CI Editor token here. Use a temporary bootstrap
# credential authorized only for the initial Worker creation, then revoke it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$ROOT/control-plane/cloudflare/wrangler.toml"
FOUNDATION="$ROOT/control-plane/cloudflare/production-foundation.json"
WRANGLER_VERSION="${WRANGLER_VERSION:-4.141.0}"
ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"

# Gate first: only Worker + CI-token blockers may remain. Reject D1, global
# operator bearer, generic Supabase secrets, and any binding drift.
python "$ROOT/scripts/cloudflare/check_deploy_readiness.py" --bootstrap
bash "$ROOT/scripts/cloudflare/assert-current-main.sh" "$ROOT"

: "${CLOUDFLARE_API_TOKEN:?Temporary bootstrap CLOUDFLARE_API_TOKEN is required}"

WORKER_NAME="$(python - "$FOUNDATION" <<'PY'
import json, sys
from pathlib import Path
foundation = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(foundation["worker_name"])
PY
)"
WORKERS_SUBDOMAIN="$(python - "$FOUNDATION" <<'PY'
import json, sys
from pathlib import Path
foundation = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(foundation["workers_dev_subdomain"])
PY
)"

tmp_response="$(mktemp)"
trap 'rm -f "$tmp_response"' EXIT
base="https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID"

cloudflare_get() {
  curl --silent --show-error --output "$tmp_response" --write-out '%{http_code}' \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    "$1"
}

# Require pre-existing, canonical workers.dev account configuration.
subdomain_status="$(cloudflare_get "$base/workers/subdomain")"
if [[ "$subdomain_status" != "200" ]]; then
  echo "Cannot inspect the dedicated Cloudflare workers.dev subdomain" >&2
  exit 4
fi
observed_subdomain="$(python - "$tmp_response" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    response=json.load(stream)
print((response.get("result") or {}).get("subdomain") or "")
PY
)"
if [[ "$observed_subdomain" != "$WORKERS_SUBDOMAIN" ]]; then
  echo "Cloudflare workers.dev subdomain differs from the canonical foundation" >&2
  exit 4
fi

# A bootstrap token is never used to update an existing Worker.
script_status="$(cloudflare_get "$base/workers/scripts/$WORKER_NAME")"
case "$script_status" in
  404) ;;
  200)
    echo "Worker already exists; initial bootstrap is not a routine update mechanism" >&2
    exit 4
    ;;
  *)
    echo "Cannot establish whether Worker already exists (HTTP $script_status)" >&2
    exit 4
    ;;
esac

npm install --ignore-scripts --no-audit --no-fund --package-lock=false \
  --prefix "$ROOT/control-plane/cloudflare"
# Narrow the race with concurrent merges after dependency/API checks.
bash "$ROOT/scripts/cloudflare/assert-current-main.sh" "$ROOT"
npx --yes "wrangler@${WRANGLER_VERSION}" deploy --config "$CONFIG"

# Confirm existence at the expected account/name after the single publication.
script_status="$(cloudflare_get "$base/workers/scripts/$WORKER_NAME")"
if [[ "$script_status" != "200" ]]; then
  echo "Initial Worker publication could not be verified" >&2
  exit 4
fi
python - "$tmp_response" "$WORKER_NAME" <<'PY'
import json, sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
result=data.get("result") or {}
if data.get("success") is not True or result.get("id") != sys.argv[2]:
    raise SystemExit("Initial Worker identity could not be verified")
PY

echo "Initial Worker created and verified: $WORKER_NAME"
echo "Revoke the temporary bootstrap API token. Then provision CI Editor scoped only to this Worker."
echo "Routine deploy is still fail-closed until the canonical foundation has no blockers."
