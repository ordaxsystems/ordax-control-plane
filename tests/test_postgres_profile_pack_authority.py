"""Source contract checks for the narrow Profile Pack assignment authority."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = (
    ROOT / "control-plane" / "supabase" / "migrations"
    / "20261007201500_profile_pack_assignment_authority_v1.sql"
)
FK_SQL = (
    ROOT / "control-plane" / "supabase" / "migrations"
    / "20261007202000_memory_and_pack_audit_fk_indexes.sql"
)


class ProfilePackAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()
        cls.fk_sql = FK_SQL.read_text(encoding="utf-8").lower()

    def test_only_space_selection_is_mutable(self):
        sql = self.sql
        self.assertIn("create role ordax_profile_pack_executor", sql)
        self.assertIn("nologin", sql)
        self.assertIn("noinherit", sql)
        self.assertIn("nobypassrls", sql)
        self.assertIn("direct table or sequence access", sql)
        self.assertIn("ordax_select_space_profile_pack_v1", sql)
        self.assertIn("ordax_clear_space_profile_pack_v1", sql)
        self.assertNotIn("insert into public.ordax_profile_packs", sql)
        self.assertNotIn("update public.ordax_profile_packs", sql)
        self.assertNotIn("insert into public.ordax_entitlement_grants", sql)
        self.assertNotIn("update public.ordax_entitlement_grants", sql)

    def test_subject_scope_and_published_pack_are_required(self):
        sql = self.sql
        self.assertIn("ordax_subject_can_admin_space_v1", sql)
        self.assertIn("v_space_state <> 'active'", sql)
        self.assertIn("state='active'", sql)
        self.assertIn("for share", sql)
        self.assertIn("for update", sql)
        self.assertIn("pack_not_active", sql)
        self.assertIn("'{}'::jsonb", sql)

    def test_access_is_explicit_and_audited(self):
        sql = self.sql
        self.assertIn("private.ordax_space_profile_pack_events", sql)
        self.assertIn("enable row level security", sql)
        self.assertIn("from public,anon,authenticated,service_role", sql)
        self.assertIn("to ordax_profile_pack_executor;", sql)
        self.assertNotIn("to service_role;", sql)
        self.assertNotIn("to authenticated;", sql)
        self.assertIn("direct table or sequence access", sql)
        self.assertIn("unexpected rpc access", sql)
        self.assertIn("unexpected role membership", sql)
        self.assertIn("'changed',false", sql)

    def test_client_cannot_supply_an_unreviewed_config(self):
        sql = self.sql
        self.assertNotIn("p_config", sql)
        self.assertIn("config=excluded.config", sql)
        self.assertIn("'{}'::jsonb", sql)

    def test_index_hardening_matches_exact_foreign_keys(self):
        sql = self.fk_sql
        self.assertIn("ordax_memory_items_project_space_fk", sql)
        self.assertIn("ordax_space_profile_pack_events_actor_user_id_fkey", sql)
        self.assertIn("ordax_memory_items(project_id,space_id)", sql)
        self.assertIn("ordax_space_profile_pack_events(actor_user_id)", sql)
        self.assertIn("indisvalid", sql)
        self.assertIn("indisready", sql)
        self.assertNotIn("if not exists", sql.split("create index",1)[1])


if __name__ == "__main__":
    unittest.main()
