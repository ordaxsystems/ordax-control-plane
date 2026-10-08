"""Contract tests: effective entitlement reads and canonical replay semantics."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "control-plane" / "supabase" / "migrations" / (
    "20261007205500_entitlement_effective_read_and_replay_v1.sql"
)


class EntitlementEffectiveStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = PATH.read_text(encoding="utf-8").lower()

    def test_replay_checks_live_grant_and_revocation_journal(self):
        sql = self.sql
        self.assertIn("create or replace function public.ordax_issue_account_default_entitlement_v2", sql)
        self.assertIn("for share of u,a", sql)
        self.assertIn("g.grant_id=v_event.grant_id", sql)
        self.assertIn("g.user_id=p_subject_user_id", sql)
        self.assertIn("g.entitlement_key=p_entitlement_key", sql)
        self.assertIn("g.source_event_id=v_source_event_id", sql)
        self.assertIn("g.valid_from<=v_now", sql)
        self.assertIn("g.valid_until>v_now", sql)
        self.assertIn("revoked.event_kind='revoked'", sql)
        self.assertIn("'account_default_grant_inactive'", sql)
        self.assertIn("'ok',false,'changed',false,'replayed',true", sql)

    def test_authenticated_reads_only_effective_grants(self):
        sql = self.sql
        self.assertIn("alter policy ordax_entitlement_grants_select_subject", sql)
        self.assertIn("on public.ordax_entitlement_grants", sql)
        self.assertIn("valid_from<=pg_catalog.statement_timestamp()", sql)
        self.assertIn("valid_until>pg_catalog.statement_timestamp()", sql)
        self.assertIn("user_id=(select auth.uid())", sql)
        self.assertIn("private.ordax_can_access_space(space_id)", sql)
        self.assertNotIn("drop policy", sql)
        self.assertNotIn("create policy", sql)

    def test_acl_and_source_authority_unchanged(self):
        sql = self.sql
        self.assertIn("account_creation_not_verified", sql)
        self.assertIn("u.deleted_at is null", sql)
        self.assertIn("u.is_anonymous is false", sql)
        self.assertIn("u.confirmed_at is not null", sql)
        self.assertIn("and state='active'", sql)
        self.assertIn("has_function_privilege(", sql)
        self.assertIn("'service_role'", sql)
        self.assertNotIn("grant execute", sql)
        self.assertNotIn("create role", sql)
        self.assertNotIn("grant insert", sql)
        self.assertNotIn("create function public.ordax_revoke_", sql)


if __name__ == "__main__":
    unittest.main()
