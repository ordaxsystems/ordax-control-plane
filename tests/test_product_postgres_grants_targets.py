from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007160500_product_capability_contract_v1.sql"
GRANT_MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007161000_product_grant_groups_v1.sql"
ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"


class ProductPostgresGrantTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capability_sql = CAPABILITY_MIGRATION.read_text(encoding="utf-8")
        cls.grant_sql = GRANT_MIGRATION.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_capability_validation_has_one_canonical_contract(self) -> None:
        self.assertIn(
            "private.ordax_product_capability_name_valid",
            self.capability_sql,
        )
        self.assertIn("^[a-z][a-z0-9._-]+$", self.capability_sql)
        self.assertIn(
            "check (private.ordax_product_capability_name_valid(capability))",
            self.capability_sql,
        )
        self.assertIn(
            "not private.ordax_product_capability_name_valid(p_capability)",
            self.capability_sql,
        )
        self.assertIn(
            "not private.ordax_product_capability_name_valid(item)",
            self.grant_sql,
        )
        self.assertNotIn("^[a-z][a-z0-9.-]+$", self.grant_sql)

    def test_grants_are_grouped_and_replaceable(self) -> None:
        lowered = self.grant_sql.lower()
        self.assertIn("grant_group_id", lowered)
        self.assertIn("profile_key", lowered)
        self.assertIn("ordax_replace_remote_grant_group_v1", lowered)
        self.assertIn("ordax_revoke_remote_grant_group_v1", lowered)
        self.assertIn("set state = 'revoked'", lowered)
        self.assertIn("client_id is not distinct from p_client_id", lowered)
        self.assertIn("space_id is not distinct from p_space_id", lowered)
        self.assertIn("project_id is not distinct from p_project_id", lowered)

    def test_device_grant_is_owner_scoped_without_space(self) -> None:
        lowered = self.grant_sql.lower()
        self.assertIn("device_grant_space_not_allowed", lowered)
        self.assertIn("d.owner_user_id = p_owner_user_id", lowered)
        self.assertIn("d.state = 'active'", lowered)

    def test_project_grant_requires_real_space_and_binding(self) -> None:
        lowered = self.grant_sql.lower()
        for token in (
            "project_grant_space_required",
            "space_admin_required",
            "project_not_found",
            "space_device_execute_required",
            "project_device_binding_required",
            "capability_not_bound_to_project",
        ):
            self.assertIn(token, lowered)
        self.assertIn("m.role in ('owner','admin')", lowered)
        self.assertIn("capability = any(v_binding.allowed_capabilities)", lowered)

    def test_targets_come_from_active_grant_groups(self) -> None:
        lowered = self.grant_sql.lower()
        self.assertIn("ordax_list_product_targets_v1", lowered)
        self.assertIn("g.state = 'active'", lowered)
        self.assertIn("g.valid_until is null or g.valid_until >", lowered)
        self.assertIn("'grant_groups'", lowered)
        self.assertIn("'capabilities'", lowered)
        self.assertIn("'online'", lowered)

    def test_grant_rpcs_are_backend_only(self) -> None:
        lowered = self.grant_sql.lower()
        for rpc in (
            "ordax_replace_remote_grant_group_v1",
            "ordax_revoke_remote_grant_group_v1",
            "ordax_list_product_targets_v1",
        ):
            self.assertIn(f"grant execute on function public.{rpc}", lowered)
        self.assertIn("from public, anon, authenticated", lowered)
        self.assertIn("to service_role;", lowered)

    def test_worker_adapter_uses_rpc_grant_boundary(self) -> None:
        for method in (
            "replaceRemoteGrantGroup",
            "revokeRemoteGrantGroup",
            "listProductTargets",
        ):
            self.assertIn(f"function {method}", self.adapter)
        for rpc in (
            "ordax_replace_remote_grant_group_v1",
            "ordax_revoke_remote_grant_group_v1",
            "ordax_list_product_targets_v1",
        ):
            self.assertIn(rpc, self.adapter)
        self.assertNotIn("/rest/v1/ordax_remote_capability_grants", self.adapter)


if __name__ == "__main__":
    unittest.main()
