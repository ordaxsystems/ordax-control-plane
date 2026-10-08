#!/usr/bin/env bash
# Retired D1 bootstrap. The OrdaX destination is PostgreSQL/Hyperdrive + R2.
# Keep this fail-closed entrypoint only to stop legacy callers from
# provisioning D1 or publishing a Worker with a global operator bearer.
set -euo pipefail
echo "Legacy D1/bootstrap deployment has been retired. Use the canonic Cloudflare deployment gate and the dedicated PostgreSQL/Hyperdrive architecture." >&2
exit 3
