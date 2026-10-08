"""Product list/status reads require live canonical Auth owner eligibility.

Service must authenticate the caller and bind the explicit owner ID to the
verified principal; this RPC defends against stale owner eligibility only.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007213000_product_owner_read_eligibility_v1.sql"
)


class ProductOwnerReadEligibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = FILE.read_text(encoding="utf-8").lower()

    def test_reuses_locked_auth_authority_with_no_second_helper(self):
        s = self.sql
        self.assertEqual(
            s.count("when not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)"),
            2,
        )
        self.assertEqual(s.count("'product_owner_auth_ineligible'"), 2)
        self.assertNotIn("create function private.", s)
        self.assertNotIn("create role ", s)
        self.assertNotIn("grant execute", s)
        self.assertNotIn("grant select", s)
        self.assertNotIn("alter policy", s)

    def test_existing_read_scopes_and_output_shape_remain(self):
        s = self.sql
        self.assertIn(
            "create or replace function public.ordax_get_product_action_v1(", s
        )
        self.assertIn(
            "create or replace function public.ordax_list_product_targets_v1(", s
        )
        self.assertEqual(s.count("create or replace function public.ordax_"), 2)
        self.assertEqual(s.count("volatile security definer"), 2)
        self.assertIn("r.owner_user_id = p_owner_user_id", s)
        self.assertIn("r.client_kind = p_client_kind", s)
        self.assertIn("r.client_id = p_client_id", s)
        self.assertIn("r.request_id = p_request_id", s)
        self.assertIn("g.owner_user_id = p_owner_user_id", s)
        self.assertIn("g.client_kind = p_client_kind", s)
        self.assertIn("g.client_id is not distinct from p_client_id", s)
        self.assertIn("g.state = 'active'", s)
        self.assertIn("'targets'", s)
        self.assertIn("'status'", s)
        self.assertNotIn("create or replace function public.ordax_revoke_remote_grant_group",s)

    def test_expected_owners_and_acl_pinned(self):
        s = self.sql
        self.assertIn("definition_md5", s) if "definition_md5" in s else self.assertIn(
            "md5(pg_get_functiondef", s
        )
        self.assertIn("pg_get_userbyid(p.proowner)<>'postgres'",s)
        self.assertIn("has_function_privilege('ordax_edge_executor',p.oid,'execute')",s)
        self.assertIn("has_function_privilege('authenticated',p.oid,'execute')",s)
        self.assertIn("has_function_privilege('service_role',p.oid,'execute')",s)
        self.assertIn("has_schema_privilege('ordax_edge_executor','private','usage')",s)
        self.assertNotIn("grant usage",s)

if __name__ == "__main__":
    unittest.main()
