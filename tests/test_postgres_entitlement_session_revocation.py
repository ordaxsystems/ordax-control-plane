"""Live Auth session binding for sensitive entitlement RLS reads."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007211000_entitlement_session_revocation_v1.sql"
)


class LiveSessionAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_claim_bound_to_canonical_session_and_user(self):
        s = self.sql
        self.assertIn("create or replace function private.ordax_authenticated_entitlement_eligible_v1()", s)
        self.assertIn("v_claims:=auth.jwt()", s)
        self.assertIn("v_subject_user_id:=auth.uid()", s)
        self.assertIn("pg_catalog.jsonb_typeof(v_claims->'session_id')<>'string'", s)
        self.assertIn("v_session_id:=v_session_text::uuid", s)
        self.assertIn("from auth.sessions s", s)
        self.assertIn("join auth.users u on u.id=s.user_id", s)
        self.assertIn("s.id=v_session_id", s)
        self.assertIn("s.user_id=v_subject_user_id", s)
        self.assertIn("s.not_after>pg_catalog.clock_timestamp()", s)

    def test_old_subject_and_suspension_checks_retained(self):
        s = self.sql
        self.assertIn("join public.ordax_accounts a on a.user_id=u.id", s)
        self.assertIn("u.deleted_at is null", s)
        self.assertIn("u.is_anonymous is false", s)
        self.assertIn("u.confirmed_at is not null", s)
        self.assertIn("u.banned_until<=pg_catalog.clock_timestamp()", s)
        self.assertIn("security definer", s)
        self.assertIn("set search_path = ''", s)
        self.assertIn("language plpgsql", s)
        self.assertIn("volatile", s)
        self.assertNotIn("create function public.ordax_", s)

    def test_acl_and_rls_policy_not_replaced(self):
        s = self.sql
        self.assertIn("ordax_entitlement_grants_select_subject", s)
        self.assertIn("has_function_privilege(", s)
        self.assertIn("'authenticated'", s)
        self.assertIn("'anon'", s)
        self.assertIn("'service_role'", s)
        self.assertIn("'private','usage'", s)
        self.assertIn("'auth.sessions','select'", s)
        self.assertNotIn("create policy ", s)
        self.assertNotIn("alter policy ", s)
        self.assertNotIn("grant execute", s)
        self.assertNotIn("create role", s)
        self.assertNotIn("grant select", s)
        self.assertNotIn("create table", s)


if __name__ == "__main__":
    unittest.main()
