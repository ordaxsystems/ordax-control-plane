"""Account-origin default entitlement boundary, replacing unsafe caller-supplied event IDs."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007203500_account_default_origin_v2.sql"


class AccountDefaultOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_source_event_is_derived_from_canonical_account(self):
        s = self.sql
        self.assertIn("public.ordax_issue_account_default_entitlement_v2(", s)
        self.assertIn("'account_created:' || p_subject_user_id::text || ':' || p_entitlement_key", s)
        self.assertIn("from auth.users u", s)
        self.assertIn("join public.ordax_accounts a on a.user_id=u.id", s)
        self.assertIn("u.deleted_at is null", s)
        self.assertIn("for key share of u,a", s)
        self.assertIn("account_creation_not_verified", s)
        self.assertNotIn("p_source_event_id", s)

    def test_reviewed_policy_only_and_single_source_event(self):
        s = self.sql
        self.assertIn("private.ordax_default_entitlement_policies", s)
        self.assertIn("and state='active'", s)
        self.assertIn("default_policy_not_active", s)
        self.assertIn("account_default_event_conflict", s)
        self.assertIn("'ordax.default.subject:'", s)
        self.assertIn("default_entitlement_already_active", s)
        self.assertIn("event_kind='issued'", s)
        self.assertIn("source_event_id=v_source_event_id", s)
        self.assertNotIn("p_entitlement_value", s)
        self.assertNotIn("p_duration", s)

    def test_v1_unverified_issue_and_revoke_apis_are_removed(self):
        s = self.sql
        self.assertIn("drop function public.ordax_issue_default_entitlement_v1(uuid,text,integer,text);", s)
        self.assertIn("drop function public.ordax_revoke_default_entitlement_v1(uuid,text);", s)
        self.assertIn("check (event_kind='issued')", s)
        self.assertNotIn("create function public.ordax_revoke_", s)
        self.assertNotIn("create or replace function public.ordax_issue_default_entitlement_v1", s)

    def test_least_privilege_executor_and_no_browser_access(self):
        s = self.sql
        self.assertIn("to ordax_entitlement_default_executor;", s)
        self.assertIn("from public,anon,authenticated,service_role", s)
        self.assertIn("unexpected executor rpc", s)
        self.assertIn("direct database authority survived", s)
        self.assertIn("service_role", s)
        self.assertNotIn("to authenticated;", s)
        self.assertNotIn("to service_role;", s)


if __name__ == "__main__":
    unittest.main()
