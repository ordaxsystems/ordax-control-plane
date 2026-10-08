"""Contract: temporary Auth suspension gates entitlements without revoking them."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007210500_entitlement_auth_suspension_v1.sql"
)


class EntitlementAuthSuspensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_issuer_checks_live_suspension_under_auth_lock(self):
        s = self.sql
        self.assertIn("create or replace function public.ordax_issue_account_default_entitlement_v2", s)
        self.assertIn("u.banned_until is null", s)
        self.assertIn("u.banned_until<=pg_catalog.clock_timestamp()", s)
        self.assertIn("for share of u,a;", s)
        self.assertLess(s.index("for share of u,a;"), s.index("select * into v_event"))
        self.assertIn("'account_creation_not_verified'", s)

    def test_rls_checks_canonical_auth_with_no_caller_subject_arg(self):
        s = self.sql
        self.assertIn("create function private.ordax_authenticated_entitlement_eligible_v1()", s)
        self.assertIn("security definer", s)
        self.assertIn("set search_path = ''", s)
        self.assertIn("where u.id=(select auth.uid())", s)
        self.assertIn("u.deleted_at is null", s)
        self.assertIn("u.is_anonymous is false", s)
        self.assertIn("u.confirmed_at is not null", s)
        self.assertIn("alter policy ordax_entitlement_grants_select_subject", s)
        self.assertIn("valid_from<=pg_catalog.clock_timestamp()", s)
        self.assertIn("private.ordax_can_access_space(space_id)", s)
        self.assertNotIn("create policy", s)

    def test_no_direct_auth_or_billing_privileges(self):
        s = self.sql
        self.assertIn("to authenticated;", s)
        self.assertIn("has_schema_privilege('authenticated','private','usage')", s)
        self.assertIn("has_table_privilege('authenticated','auth.users','select')", s)
        self.assertIn("has_function_privilege('service_role'", s)
        self.assertNotIn("grant usage on schema private", s)
        self.assertNotIn("grant select on auth.users", s)
        self.assertNotIn("grant execute on function public.ordax_issue", s)
        self.assertNotIn("create role", s)
        self.assertNotIn("update public.ordax_entitlement_grants", s)


if __name__ == "__main__":
    unittest.main()
