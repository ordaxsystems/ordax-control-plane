import json
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-v3-deploy.yml"
BOOTSTRAP = ROOT / "scripts" / "cloudflare" / "deploy-v3.sh"
ROUTINE_DEPLOY = ROOT / "scripts" / "cloudflare" / "deploy-production-v3.sh"
FOUNDATION = ROOT / "control-plane" / "cloudflare" / "production-foundation.json"
WRANGLER = ROOT / "control-plane" / "cloudflare" / "wrangler.toml"
POSTGRES_ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"
WORKER_SOURCE = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
CLOUDFLARE_SRC = ROOT / "control-plane" / "cloudflare" / "src"
CLOUDFLARE_MIGRATIONS = ROOT / "control-plane" / "cloudflare" / "migrations"

OLD_ACCOUNT_ID = "ac1ca1b50d09c7a4cb81274d2aa1e78f"
DEDICATED_ACCOUNT_ID = "42586bf13b61436219d21def299833e4"

LEGACY_D1_SOURCE_ALLOWLIST = {
    "index.ts",
    "product_device_grants.ts",
    "product_intelligence_grants.ts",
    "product_project_grants.ts",
    "retention.ts",
}
LEGACY_D1_MIGRATION_ALLOWLIST = {
    "0001_initial.sql",
    "0002_device_enrollment.sql",
    "0003_terminal_report_replay.sql",
    "0004_artifact_multipart_uploads.sql",
    "0005_product_grants_audit.sql",
    "0006_product_action_requests.sql",
    "0007_product_device_pairing.sql",
    "0008_product_device_owner.sql",
}
LEGACY_D1_TABLE_ALLOWLIST = {
    "ordax_devices",
    "ordax_jobs",
    "ordax_job_events",
    "ordax_artifacts",
    "ordax_artifact_uploads",
    "ordax_product_grants",
    "ordax_product_audit",
    "ordax_product_action_requests",
    "ordax_product_device_pairings",
    "ordax_product_device_links",
}


class CloudflareAccountResolutionContractTests(unittest.TestCase):
    def test_production_foundation_is_canonical_and_forbids_legacy_persistence(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        self.assertEqual(foundation["account_id"], DEDICATED_ACCOUNT_ID)
        self.assertEqual(foundation["authorities"]["persistent"], "postgresql")
        self.assertEqual(foundation["authorities"]["artifacts"], "r2")
        self.assertEqual(
            foundation["authorities"]["realtime_session_coordination"],
            "durable_objects",
        )
        self.assertFalse(foundation["policy"]["allow_d1"])
        self.assertFalse(foundation["policy"]["allow_dual_write"])
        self.assertTrue(foundation["security"]["require_two_factor"])
        self.assertEqual(foundation["postgres"]["runtime_transport"], "hyperdrive")
        self.assertEqual(foundation["postgres"]["hyperdrive_binding"], "POSTGRES")
        self.assertEqual(foundation["postgres"]["query_cache"], "disabled")
        self.assertIn(
            "SUPABASE_SERVER_KEY",
            foundation["policy"]["forbidden_runtime_secrets"],
        )
        self.assertIn(
            "SUPABASE_SERVICE_ROLE_KEY",
            foundation["policy"]["forbidden_runtime_secrets"],
        )
        self.assertEqual(foundation["workers_dev_subdomain"], "ordaxsystems")
        self.assertNotIn(
            "workers_dev_subdomain_not_initialized",
            foundation["readiness_blockers"],
        )
        self.assertNotIn(
            "product_auth_metadata_not_repointed",
            foundation["readiness_blockers"],
        )
        self.assertEqual(
            foundation["deployment"]["bootstrap_authority"],
            "temporary_workers_product_admin",
        )
        self.assertEqual(
            foundation["deployment"]["routine_authority"],
            "existing_worker_editor",
        )
        self.assertTrue(
            foundation["deployment"]["routine_requires_existing_worker"],
        )
        blockers = set(foundation["readiness_blockers"])
        self.assertIn("r2_bucket_not_provisioned", blockers)
        self.assertIn("worker_not_provisioned", blockers)
        self.assertIn(
            "cloudflare_ci_worker_editor_token_not_provisioned",
            blockers,
        )
        self.assertNotIn("cloudflare_ci_token_not_rotated", blockers)

    def test_legacy_d1_surface_is_frozen_while_cutover_is_incomplete(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        blockers = set(foundation["readiness_blockers"])
        d1_sources = set()
        referenced_tables = set()

        table_pattern = re.compile(
            r"\\b(?:from|join|into|update|table)\\s+(ordax_[a-z0-9_]+)",
            re.IGNORECASE,
        )
        for path in CLOUDFLARE_SRC.glob("*.ts"):
            source = path.read_text(encoding="utf-8")
            if (
                "D1Database" in source
                or "env.DB" in source
                or "this.env.DB" in source
            ):
                d1_sources.add(path.name)
                referenced_tables.update(
                    match.lower() for match in table_pattern.findall(source)
                )

        migrations = {path.name for path in CLOUDFLARE_MIGRATIONS.glob("*.sql")}

        self.assertTrue(
            d1_sources.issubset(LEGACY_D1_SOURCE_ALLOWLIST),
            f"new D1 source files are forbidden: {sorted(d1_sources - LEGACY_D1_SOURCE_ALLOWLIST)}",
        )
        self.assertTrue(
            migrations.issubset(LEGACY_D1_MIGRATION_ALLOWLIST),
            f"new D1 migrations are forbidden: {sorted(migrations - LEGACY_D1_MIGRATION_ALLOWLIST)}",
        )
        self.assertTrue(
            referenced_tables.issubset(LEGACY_D1_TABLE_ALLOWLIST),
            f"new D1 tables are forbidden: {sorted(referenced_tables - LEGACY_D1_TABLE_ALLOWLIST)}",
        )

        if d1_sources or migrations:
            self.assertFalse(foundation["policy"]["allow_d1"])
            self.assertIn("worker_d1_cutover_incomplete", blockers)

    def test_product_auth_metadata_is_derived_from_canonical_project_ref(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as handle:
            wrangler = tomllib.load(handle)
        project_ref = foundation["postgres"]["project_ref"]
        auth_origin = f"https://{project_ref}.supabase.co/auth/v1"
        self.assertEqual(
            wrangler["vars"]["PRODUCT_AUTH_ISSUER"],
            auth_origin,
        )
        self.assertEqual(
            wrangler["vars"]["PRODUCT_AUTH_JWKS_URL"],
            f"{auth_origin}/.well-known/jwks.json",
        )
        self.assertEqual(wrangler["vars"]["PRODUCT_AUTH_AUDIENCE"], "authenticated")
        self.assertNotIn("eobcxuyvhkvdmkbaihwh", WRANGLER.read_text(encoding="utf-8"))

    def test_legacy_operator_bearer_keeps_production_blocked(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        blockers = set(foundation["readiness_blockers"])
        forbidden = set(foundation["policy"]["forbidden_runtime_secrets"])
        if "ORDAX_OPERATOR_TOKEN" in source or "operatorAuthorized(" in source:
            self.assertIn("worker_operator_auth_cutover_incomplete", blockers)
            self.assertIn("ORDAX_OPERATOR_TOKEN", forbidden)

    def test_legacy_rest_adapter_keeps_production_blocked_until_hyperdrive_cutover(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        adapter = POSTGRES_ADAPTER.read_text(encoding="utf-8")
        blockers = set(foundation["readiness_blockers"])
        if "SUPABASE_SERVER_KEY" in adapter or "/rest/v1/rpc/" in adapter:
            self.assertIn("worker_hyperdrive_adapter_not_implemented", blockers)

    def test_routine_workflow_reads_account_from_single_source_of_truth(self):
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertNotIn("secrets.CLOUDFLARE_ACCOUNT_ID", workflow)
        self.assertNotIn(OLD_ACCOUNT_ID, workflow)
        self.assertNotIn(DEDICATED_ACCOUNT_ID, workflow)
        self.assertIn("control-plane/cloudflare/production-foundation.json", workflow)
        self.assertIn("needs.foundation.outputs.account_id", workflow)
        self.assertIn("needs.foundation.outputs.deployment_ready == 'true'", workflow)
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("secrets.ORDAX_OPERATOR_TOKEN", workflow)
        self.assertIn('runtime_transport") != "hyperdrive"', workflow)
        self.assertIn('hyperdrive_binding") != "POSTGRES"', workflow)
        self.assertIn('query_cache") != "disabled"', workflow)
        self.assertIn("generic Supabase server secrets must be forbidden", workflow)

    def test_not_ready_foundation_skips_deploy_instead_of_creating_false_incident(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertFalse(foundation["deployment_ready"])
        self.assertTrue(foundation["readiness_blockers"])
        self.assertIn("foundation:", workflow)
        self.assertIn("deploy:", workflow)
        self.assertNotIn("Enforce dedicated-account migration gate", workflow)

    def test_legacy_bootstrap_cannot_create_d1_in_dedicated_account(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("production-foundation.json", script)
        self.assertIn(
            "Refusing legacy D1 bootstrap on the dedicated OrdaX Cloudflare account.",
            script,
        )
        self.assertIn('if [[ "$CLOUDFLARE_ACCOUNT_ID" == "$TARGET_ACCOUNT_ID" ]]', script)

    def test_privileged_bootstrap_can_still_resolve_non_target_account_fail_closed(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("/client/v4/accounts?per_page=50", script)
        self.assertIn("len(ids) != 1", script)
        self.assertIn("set CLOUDFLARE_ACCOUNT_ID explicitly", script)
        self.assertNotIn("CLOUDFLARE_ACCOUNT_ID is required", script)

    def test_routine_deploy_has_no_legacy_account_or_workers_dev_url_fallback(self):
        script = ROUTINE_DEPLOY.read_text(encoding="utf-8")
        self.assertNotIn(OLD_ACCOUNT_ID, script)
        self.assertNotIn("ordax-ac1ca1b50d09", script)
        self.assertIn(
            'ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"',
            script,
        )
        self.assertIn("/workers/subdomain", script)
        self.assertNotIn("workers/subdomain\" -X PUT", script)


if __name__ == "__main__":
    unittest.main()
