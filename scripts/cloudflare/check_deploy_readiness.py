#!/usr/bin/env python3
"""Single deploy-readiness gate for the OrdaX Cloudflare production Worker.

The GitHub workflow may validate a blocked foundation; direct deploy scripts
must reject it before any Cloudflare API requests or Wrangler invocation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.toml"
WORKER_SOURCES = ROOT / "control-plane/cloudflare/src"


class DeployGateError(ValueError):
    pass


def validate(data: dict, config: dict, source: str, account_id: str | None = None) -> bool:
    canonical_account = data.get("account_id")
    if not isinstance(canonical_account, str) or not re.fullmatch(r"[0-9a-f]{32}", canonical_account):
        raise DeployGateError("invalid canonical account ID")
    if account_id is not None and account_id != canonical_account:
        raise DeployGateError("deploy account differs from canonical Cloudflare account")

    worker_name = data.get("worker_name")
    if not isinstance(worker_name, str) or config.get("name") != worker_name:
        raise DeployGateError("Worker name differs from canonical foundation")

    authorities = data.get("authorities") or {}
    if (authorities.get("persistent"), authorities.get("artifacts"),
            authorities.get("realtime_session_coordination")) != (
            "postgresql", "r2", "durable_objects"):
        raise DeployGateError("non-canonical persistent/artifact/realtime authorities")

    policy = data.get("policy") or {}
    if policy.get("allow_d1") is not False or policy.get("allow_dual_write") is not False:
        raise DeployGateError("D1 or dual-write permitted by foundation")
    forbidden = set(policy.get("forbidden_runtime_secrets") or [])
    if not {"SUPABASE_SERVER_KEY", "SUPABASE_SERVICE_ROLE_KEY", "ORDAX_OPERATOR_TOKEN"}.issubset(forbidden):
        raise DeployGateError("forbidden runtime secrets policy incomplete")
    if (data.get("security") or {}).get("require_two_factor") is not True:
        raise DeployGateError("2FA security requirement missing")

    postgres = data.get("postgres") or {}
    if postgres.get("runtime_transport") != "hyperdrive" or postgres.get("hyperdrive_binding") != "POSTGRES":
        raise DeployGateError("PostgreSQL transport/binding must use Hyperdrive POSTGRES")
    if postgres.get("query_cache") != "disabled":
        raise DeployGateError("Hyperdrive query cache must be disabled")
    evidence = (data.get("live_evidence") or {}).get("hyperdrive") or {}
    hyperdrive = config.get("hyperdrive") or []
    if (not isinstance(hyperdrive, list) or len(hyperdrive) != 1
            or hyperdrive[0].get("binding") != "POSTGRES"
            or hyperdrive[0].get("id") != evidence.get("id")
            or evidence.get("name") != data.get("hyperdrive_name")
            or evidence.get("runtime_role") != postgres.get("runtime_role")
            or evidence.get("query_cache_disabled") is not True
            or evidence.get("sslmode") != "require"):
        raise DeployGateError("Hyperdrive binding/evidence mismatch")

    bindings = (config.get("durable_objects") or {}).get("bindings") or []
    if not isinstance(bindings, list) or {
        (item.get("name"), item.get("class_name")) for item in bindings
    } != {
        ("DEVICE_SESSIONS", "DeviceSession"),
        ("ENROLLMENT_SESSIONS", "EnrollmentSession"),
    }:
        raise DeployGateError("non-canonical Durable Objects bindings")

    buckets = config.get("r2_buckets") or []
    if (not isinstance(buckets, list) or len(buckets) != 1
            or buckets[0].get("binding") != "ARTIFACTS"
            or buckets[0].get("bucket_name") != data.get("r2_bucket")):
        raise DeployGateError("R2 bucket binding differs from canonical authority")

    ready = data.get("deployment_ready")
    blockers = data.get("readiness_blockers")
    if not isinstance(ready, bool) or not isinstance(blockers, list):
        raise DeployGateError("invalid deployment readiness structure")
    if any(not isinstance(blocker, str) or not blocker for blocker in blockers):
        raise DeployGateError("invalid readiness blocker")
    if len(blockers) != len(set(blockers)):
        raise DeployGateError("duplicate readiness blockers")
    if ready == bool(blockers):
        raise DeployGateError("deployment_ready contradicts readiness blockers")

    if ready:
        if config.get("d1_databases"):
            raise DeployGateError("D1 binding remains in production Wrangler")
        if "env.DB" in source or "D1Database" in source:
            raise DeployGateError("legacy D1 access remains in Worker source")
        if "ORDAX_OPERATOR_TOKEN" in source or "operatorAuthorized(" in source:
            raise DeployGateError("legacy global operator bearer remains in Worker source")
        if "SUPABASE_SERVER_KEY" in source or "SUPABASE_SERVICE_ROLE_KEY" in source:
            raise DeployGateError("forbidden Supabase server secret remains in Worker source")
    return ready


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-blocked", action="store_true",
                        help="Validate blocked foundation without authorizing deploy (CI only)")
    parser.add_argument("--github-output", type=Path, default=None)
    args = parser.parse_args()
    try:
        data = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as stream:
            config = tomllib.load(stream)
        source_paths = sorted(WORKER_SOURCES.glob("*.ts"))
        if not source_paths:
            raise DeployGateError("Cloudflare Worker sources not found")
        source = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)
        ready = validate(data, config, source, os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Cloudflare deploy gate invalid: {error}", file=sys.stderr)
        return 2

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"account_id={data['account_id']}\n")
            stream.write(f"deployment_ready={'true' if ready else 'false'}\n")

    if not ready:
        print(f"Cloudflare production deployment BLOCKED ({len(data['readiness_blockers'])} blockers)")
        if not args.allow_blocked:
            return 3
    else:
        print("Cloudflare production deployment READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
