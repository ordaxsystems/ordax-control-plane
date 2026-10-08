"""Versioned Auth trust-loss revocation boundary for Product defaults."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL_FILE = (
    ROOT / "control-plane" / "supabase" / "migrations"
    / "20261007205000_auth_eligibility_default_revocation_v2.sql"
)


class AuthEligibilityRevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL_FILE.read_text(encoding="utf-8").lower()

    def test_revoke_all_verified_trust_loss_transitions(self):
        sql = self.sql
        self.assertIn("old.deleted_at is null and new.deleted_at is not null", sql)
        self.assertIn("old.is_anonymous is false and new.is_anonymous is true", sql)
        self.assertIn("old.confirmed_at is not null and new.confirmed_at is null", sql)
        self.assertIn("after update on auth.users", sql)
        self.assertNotIn("after update of confirmed_at", sql)
        self.assertIn("confirmed_at is a stored generated column", sql)

    def test_atomic_expiry_and_event_are_source_owned(self):
        sql = self.sql
        self.assertIn("security definer", sql)
        self.assertIn("set search_path = ''", sql)
        self.assertIn("with revoked as", sql)
        self.assertIn("update public.ordax_entitlement_grants g", sql)
        self.assertIn("g.source='product-default'", sql)
        self.assertIn("g.valid_until is null or g.valid_until>v_now", sql)
        self.assertIn("insert into private.ordax_default_entitlement_events", sql)
        self.assertIn("v_origin || r.grant_id::text", sql)
        self.assertIn("'account_deleted:'", sql)
        self.assertIn("'account_ineligible:'", sql)
        self.assertIn("auth eligibility v2: invalid trigger invocation", sql)

    def test_no_duplicated_legacy_trigger_or_client_access(self):
        sql = self.sql
        self.assertIn("drop trigger ordax_auth_user_soft_delete_default_entitlements", sql)
        self.assertIn("drop function private.ordax_revoke_defaults_on_auth_soft_delete_v1()", sql)
        self.assertIn("create trigger ordax_auth_user_ineligible_default_entitlements", sql)
        self.assertIn("revoke all on function private.ordax_revoke_defaults_on_auth_ineligible_v2()", sql)
        self.assertIn("has_function_privilege('authenticated'", sql)
        self.assertIn("has_function_privilege('service_role'", sql)
        self.assertNotIn("grant execute", sql)
        self.assertNotIn("create function public.ordax_revoke_", sql)
        self.assertIn("to_regprocedure('public.ordax_revoke_default_entitlement_v1", sql)


if __name__ == "__main__":
    unittest.main()
