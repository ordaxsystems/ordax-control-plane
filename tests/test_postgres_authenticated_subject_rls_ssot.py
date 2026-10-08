"""Canonical Auth session check is shared across private subject-bound RLS."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_FILE = ROOT / "control-plane" / "supabase" / "migrations" / "20261007211500_authenticated_subject_rls_ssot_v1.sql"


class SubjectSessionRLSSSOTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL_FILE.read_text(encoding="utf-8").lower()

    def test_single_function_renamed_not_duplicated(self):
        s = self.sql
        self.assertIn("alter function private.ordax_authenticated_entitlement_eligible_v1()",s)
        self.assertIn("rename to ordax_authenticated_subject_eligible_v1;",s)
        self.assertIn("to_regprocedure('private.ordax_authenticated_entitlement_eligible_v1()') is not null",s)
        self.assertNotIn("create function private.ordax_authenticated_subject_eligible_v1",s)
        self.assertNotIn("grant execute",s)
        self.assertNotIn("create policy",s)
        self.assertNotIn("create role",s)

    def test_private_policies_use_one_live_session_guard(self):
        s = self.sql
        targets = {
            "ordax_accounts_select_own","ordax_accounts_update_own",
            "ordax_device_presence_select_authorized",
            "ordax_device_project_bindings_select_project",
            "ordax_memory_embeddings_select_authorized",
            "ordax_memory_items_select_authorized",
            "ordax_product_devices_select_authorized",
            "ordax_project_connections_select_space",
            "ordax_projects_select_space",
            "ordax_remote_capability_grants_select_admin",
            "ordax_space_devices_select_space",
            "ordax_space_members_select_space",
            "ordax_space_profile_packs_select_member",
            "ordax_spaces_select_member",
        }
        for target in targets:
            with self.subTest(policy=target):
                self.assertIn(f"alter policy {target}",s)
        self.assertEqual(s.count("alter policy "),len(targets))
        self.assertIn("with check (",s)
        self.assertIn("v_guarded<>15",s)
        self.assertIn("ordax_profile_packs_select_active",s)
        self.assertNotIn("alter policy ordax_profile_packs_select_active",s)

    def test_acl_session_and_existing_predicates(self):
        s = self.sql
        self.assertIn("auth.sessions",s)
        self.assertIn("banned_until",s)
        self.assertIn("not_after",s)
        self.assertIn("private.ordax_can_access_space(space_id)",s)
        self.assertIn("private.ordax_can_admin_space(space_id)",s)
        self.assertIn("private.ordax_can_access_product_device(device_id)",s)
        self.assertIn("private.ordax_can_access_project(project_id)",s)
        self.assertIn("has_table_privilege('authenticated','auth.sessions','select')",s)
        self.assertIn("has_schema_privilege('authenticated','private','usage')",s)
        self.assertNotIn("grant select",s)


if __name__ == "__main__":
    unittest.main()
