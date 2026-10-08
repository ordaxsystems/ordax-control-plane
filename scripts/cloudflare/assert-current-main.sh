#!/usr/bin/env bash
# Refuse Cloudflare publication of a source tree that is no longer remote main.
# Runs after the canonical readiness gate but before any deploy credential use.
set -euo pipefail

if [[ "$#" -ne 1 || ! -d "$1" ]]; then
  echo "Repository root argument is required for source freshness verification" >&2
  exit 4
fi
ROOT="$(cd "$1" && pwd)"
if ! source_sha="$(git -C "$ROOT" rev-parse --verify HEAD^{commit} 2>/dev/null)"; then
  echo "Cannot identify deploy source commit" >&2
  exit 4
fi
if ! remote_ref="$(git -C "$ROOT" ls-remote --exit-code origin refs/heads/main 2>/dev/null)"; then
  echo "Cannot verify current remote main; refusing Cloudflare deployment" >&2
  exit 4
fi
remote_sha="${remote_ref%%[[:space:]]*}"
if [[ ! "$source_sha" =~ ^[0-9a-f]{40}$ || ! "$remote_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid source or remote main commit identifier" >&2
  exit 4
fi
if [[ "$source_sha" != "$remote_sha" ]]; then
  echo "Deploy source is stale: checkout must match current remote main" >&2
  exit 4
fi
echo "Cloudflare deploy source matches current remote main: $source_sha"
