"""Product grant/device/action issuance must recheck canonical live Auth owner."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007212500_product_owner_auth_eligibility_v1.sql"
)


class ProductOwnerAuthEligibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = PATH.read_text(encoding="utf-8").lower()

    def test_tenured_trusted_actor_helper_reused(self):
        s = self.sql
        self.assertIn("private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)",s)
        self.assertEqual(s.count("if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then"),3)
        self.assertEqual(s.count("'product_owner_auth_ineligible'"),3)
        self.assertNotIn("create function private.ordax_trusted_actor_auth_eligible",s)
        self.assertNotIn("create role ",s)

    def test_only_granting_and_execution_mutations_guarded(self):
        s = self.sql
        names = (
            "ordax_enroll_product_device_v1",
            "ordax_replace_remote_grant_group_v1",
            "ordax_enqueue_product_action_v1",
        )
        for n in names:
            with self.subTest(rpc=n):
                self.assertIn(f"create or replace function public.{n}(",s)
        self.assertEqual(s.count("create or replace function public.ordax_"),3)
        self.assertNotIn("create or replace function public.ordax_revoke_remote_grant_group_v1",s)
        self.assertNotIn("create or replace function public.ordax_record_product_presence_v1",s)
        self.assertIn("definition_md5",s)

    def test_existing_least_privilege_and_client_security(self):
        s = self.sql
        self.assertIn("has_function_privilege('ordax_edge_executor',p.oid,'execute')",s)
        self.assertIn("has_function_privilege('authenticated',p.oid,'execute')",s)
        self.assertIn("has_function_privilege('service_role',p.oid,'execute')",s)
        self.assertIn("has_schema_privilege('ordax_edge_executor','private','usage')",s)
        self.assertIn("has_table_privilege('authenticated','auth.users','select')",s)
        self.assertNotIn("grant execute",s)
        self.assertNotIn("grant usage",s)
        self.assertNotIn("grant select",s)

if __name__ == "__main__":
    unittest.main()
