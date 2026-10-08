"""Versioned Auth eligibility on trusted actor/subject RPCs.

Services authenticate the caller. PostgreSQL verifies canonical Auth
eligibility and locks the trusted actor row in the same write transaction.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007212000_trusted_actor_auth_eligibility_v1.sql"
)

RPCS = (
    "ordax_clear_space_profile_pack_v1",
    "ordax_create_memory_item_v1",
    "ordax_create_project_v1",
    "ordax_create_space_v1",
    "ordax_remove_space_member_v1",
    "ordax_select_space_profile_pack_v1",
    "ordax_set_space_member_v1",
    "ordax_update_memory_item_v1",
    "ordax_update_project_v1",
    "ordax_update_space_v1",
)


class TrustedActorEligibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = FILE.read_text(encoding="utf-8").lower()

    def test_single_private_invoker_helper_with_canonical_auth_lock(self):
        s = self.sql
        self.assertEqual(s.count("create function private.ordax_trusted_actor_auth_eligible_v1("), 1)
        self.assertIn("security invoker", s)
        self.assertIn("set search_path = ''", s)
        self.assertIn("from auth.users u", s)
        self.assertIn("join public.ordax_accounts a on a.user_id=u.id", s)
        self.assertIn("u.deleted_at is null", s)
        self.assertIn("u.is_anonymous is false", s)
        self.assertIn("u.confirmed_at is not null", s)
        self.assertIn("u.banned_until<=pg_catalog.clock_timestamp()", s)
        self.assertIn("for share of u,a", s)
        self.assertIn("return found", s)
        self.assertNotIn("create role", s)
        self.assertNotIn("create table", s)

    def test_all_ten_rpc_definitions_hardened_at_entry(self):
        s = self.sql
        for name in RPCS:
            with self.subTest(rpc=name):
                self.assertIn(f"create or replace function public.{name}(", s)
        self.assertEqual(len(re.findall(r"create or replace function public.ordax_", s)), len(RPCS))
        self.assertEqual(s.count("'trusted_actor_auth_ineligible'"), len(RPCS))
        self.assertEqual(s.count("if not private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) then"), len(RPCS))
        self.assertIn("definition_md5", s)
        self.assertIn("baseline", s) if "baseline" in s else self.assertIn("drifted", s)

    def test_acl_remains_private_and_network_identity_is_not_assumed(self):
        s = self.sql
        self.assertIn("from public, anon, authenticated, service_role", s)
        self.assertIn("has_function_privilege(", s)
        self.assertIn("'authenticated','auth.users','select'", s)
        self.assertIn("'ordax_space_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','execute'", s)
        self.assertNotIn("grant execute", s)
        self.assertNotIn("grant select", s)
        self.assertNotIn("auth.jwt()", s)
        self.assertNotIn("auth.uid()", s)


if __name__ == "__main__":
    unittest.main()
