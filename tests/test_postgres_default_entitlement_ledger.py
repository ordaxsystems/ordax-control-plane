"""Narrow default-entitlement issuance/revocation PostgreSQL authority."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "control-plane" / "supabase" / "migrations"
             / "20261007202500_default_entitlement_ledger_v1.sql")


class DefaultEntitlementLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_canonical_provenance_without_legacy_backfill(self):
        sql = self.sql
        self.assertIn("existing grants require explicit provenance migration", sql)
        self.assertIn("add column source_event_id text", sql)
        self.assertIn("add column policy_version integer", sql)
        self.assertIn("ordax_entitlements_source_event_uidx", sql)
        self.assertIn("source = 'product-default'", sql)
        self.assertNotIn("'legacy'", sql)

    def test_issuer_requires_approved_versioned_policy(self):
        sql = self.sql
        self.assertIn("private.ordax_default_entitlement_policies", sql)
        self.assertIn("primary key(entitlement_key, policy_version)", sql)
        self.assertIn("and state='active'", sql)
        self.assertIn("for share;", sql)
        self.assertIn("default_policy_not_active", sql)
        self.assertIn("entitlement_value,duration_seconds", sql)
        self.assertIn("jsonb_typeof(entitlement_value) = 'object'", sql)
        self.assertNotIn("p_entitlement_value", sql)
        self.assertNotIn("p_source text", sql)

    def test_issuance_and_revocation_have_replay_conflict_checks(self):
        sql = self.sql
        self.assertIn("unique(source, source_event_id)", sql)
        self.assertIn("source_event_conflict", sql)
        self.assertIn("ordax.default.event:", sql)
        self.assertIn("ordax.default.subject:", sql)
        self.assertIn("default_entitlement_already_active", sql)
        self.assertIn("event_kind text not null", sql)
        self.assertIn("v_event.event_kind='issued'", sql)
        self.assertIn("v_event.event_kind='revoked'", sql)
        self.assertIn("for update;", sql)
        self.assertIn("v_grant.valid_from + interval '1 microsecond'", sql)
        self.assertNotIn("delete from public.ordax_entitlement_grants", sql)

    def test_only_nologin_executor_can_call_rpcs(self):
        sql = self.sql
        self.assertIn("create role ordax_entitlement_default_executor", sql)
        self.assertIn("nologin", sql)
        self.assertIn("noinherit", sql)
        self.assertIn("nobypassrls", sql)
        self.assertIn("ordax_issue_default_entitlement_v1", sql)
        self.assertIn("ordax_revoke_default_entitlement_v1", sql)
        self.assertIn("to ordax_entitlement_default_executor;", sql)
        self.assertIn("from public,anon,authenticated,service_role", sql)
        self.assertIn("unexpected table/sequence access", sql)
        self.assertIn("unexpected public function access", sql)
        self.assertIn("unexpected executor membership", sql)
        self.assertNotIn("to service_role;", sql)
        self.assertNotIn("to authenticated;", sql)

    def test_event_history_is_private_and_no_general_billing(self):
        sql = self.sql
        self.assertIn("private.ordax_default_entitlement_events", sql)
        self.assertIn("enable row level security", sql)
        self.assertIn("on delete cascade", sql)
        self.assertNotIn("'billing'", sql)
        self.assertNotIn("'promotion'", sql)
        self.assertNotIn("'admin'", sql)
        self.assertNotIn("p_actor_user_id", sql)


if __name__ == "__main__":
    unittest.main()
