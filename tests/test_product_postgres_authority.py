from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007150000_product_remote_authority_v1.sql"
HARDENING = ROOT / "control-plane" / "supabase" / "migrations" / "20261007152000_product_remote_authority_hardening.sql"
ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"


class ProductPostgresAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.hardening = HARDENING.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_device_scope_never_requires_synthetic_project(self) -> None:
        self.assertIn("scope_kind in ('device','project')", self.sql)
        self.assertIn("alter column project_id drop not null", self.sql)
        self.assertIn("scope_kind = 'device' and project_id is null", self.sql)
        self.assertIn("scope_kind = 'project' and project_id is not null", self.sql)
        self.assertIn("foreign key (project_id, space_id)", self.sql)
        self.assertNotIn(
            "check (\n    (project_id is null)\n    or exists",
            self.sql,
        )

    def test_product_remote_queue_is_not_engineering_queue(self) -> None:
        self.assertIn(
            "create table if not exists private.ordax_product_action_requests",
            self.sql,
        )
        self.assertIn(
            "create table if not exists private.ordax_product_action_events",
            self.sql,
        )
        self.assertIn(
            "create table if not exists private.ordax_product_action_audit",
            self.sql,
        )
        self.assertNotIn("references public.ordax_develop_jobs", self.sql)
        self.assertNotIn("insert into public.ordax_develop_jobs", self.sql)
        self.assertNotIn("update public.ordax_develop_jobs", self.sql)

    def test_remote_authority_has_idempotency_fencing_and_terminal_replay(self) -> None:
        for token in (
            "unique (owner_user_id, idempotency_key)",
            "effect_id",
            "attempt_id",
            "lease_id",
            "execution_epoch",
            "agent_instance_id",
            "boot_id",
            "report_id",
            "idempotency_conflict",
            "terminal_report_conflict",
            "for update skip locked",
            "pg_advisory_xact_lock",
        ):
            self.assertIn(token, self.sql.lower())

    def test_private_tables_are_not_a_client_api(self) -> None:
        for table in (
            "private.ordax_product_action_requests",
            "private.ordax_product_action_events",
            "private.ordax_product_action_audit",
        ):
            self.assertIn(
                f"revoke all on table {table}",
                self.sql,
            )
            self.assertIn(
                f"alter table {table} enable row level security",
                self.hardening,
            )
        self.assertIn("from public, anon, authenticated, service_role", self.sql)
        self.assertIn(
            "grant execute on function public.ordax_enqueue_product_action_v1",
            self.sql,
        )
        self.assertIn("to service_role;", self.sql)

    def test_product_action_foreign_keys_are_indexed(self) -> None:
        for index_fragment in (
            "ordax_product_action_project_space_idx",
            "ordax_product_action_space_idx",
            "ordax_product_action_grant_idx",
        ):
            self.assertIn(index_fragment, self.hardening)

    def test_presence_is_coalesced_instead_of_persisting_every_heartbeat(self) -> None:
        self.assertIn("ordax_record_product_presence_v1", self.sql)
        self.assertIn("interval '5 minutes'", self.sql)
        self.assertIn("p_force boolean default false", self.sql)

    def test_worker_adapter_uses_modern_backend_secret_only(self) -> None:
        lowered = self.adapter.lower()
        self.assertIn("supabase_server_key", lowered)
        self.assertIn("sb_secret_", lowered)
        self.assertIn("apikey: serverkey", lowered)
        self.assertNotIn("authorization", lowered)
        self.assertNotIn("bearer ", lowered)
        self.assertNotIn("supabase_service_role_key", lowered)
        self.assertNotIn("d1database", lowered)

    def test_adapter_is_rpc_only_not_direct_table_mutation(self) -> None:
        self.assertIn("/rest/v1/rpc/", self.adapter)
        self.assertNotIn("/rest/v1/ordax_", self.adapter)
        for rpc in (
            "ordax_enqueue_product_action_v1",
            "ordax_claim_product_action_v1",
            "ordax_start_product_action_v1",
            "ordax_renew_product_action_lease_v1",
            "ordax_progress_product_action_v1",
            "ordax_report_product_action_v1",
            "ordax_get_product_action_v1",
            "ordax_record_product_presence_v1",
        ):
            self.assertIn(rpc, self.adapter)


if __name__ == "__main__":
    unittest.main()
