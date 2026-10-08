"""Auth soft-delete revokes product-default entitlements without an external caller."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007204000_auth_soft_delete_default_revocation_v1.sql"


class AuthSoftDeleteRevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_issuer_auth_validation_blocks_deletion_race(self):
        s = self.sql
        self.assertIn("create or replace function public.ordax_issue_account_default_entitlement_v2",s)
        self.assertIn("for share of u,a;",s)
        self.assertNotIn("for key share of u,a;",s)
        self.assertIn("u.deleted_at is null",s)
        self.assertIn("u.is_anonymous is false",s)
        self.assertIn("u.confirmed_at is not null",s)
        self.assertLess(s.index("for share of u,a;"),s.index("select * into v_event"))
        self.assertIn("account_creation_not_verified",s)

    def test_revocation_is_auth_trigger_only_and_recorded_atomically(self):
        s = self.sql
        self.assertIn("after update of deleted_at on auth.users",s)
        self.assertIn("old.deleted_at is null and new.deleted_at is not null",s)
        self.assertIn("create function private.ordax_revoke_defaults_on_auth_soft_delete_v1()",s)
        self.assertIn("security definer",s)
        self.assertIn("set search_path = ''",s)
        self.assertIn("with revoked as",s)
        self.assertIn("update public.ordax_entitlement_grants g",s)
        self.assertIn("g.source='product-default'",s)
        self.assertIn("insert into private.ordax_default_entitlement_events",s)
        self.assertIn("'account_deleted:' || r.grant_id::text",s)
        self.assertIn("check(event_kind in ('issued','revoked'))",s)
        self.assertIn("g.valid_from + interval '1 microsecond'",s)

    def test_no_generic_revoke_access(self):
        s = self.sql
        self.assertNotIn("create function public.ordax_revoke_",s)
        self.assertIn("generic revoke rpc returned",s)
        self.assertIn("from public,anon,authenticated,service_role",s)
        self.assertIn("privilege regression",s)
        self.assertNotIn("grant execute",s)


if __name__ == "__main__":
    unittest.main()
