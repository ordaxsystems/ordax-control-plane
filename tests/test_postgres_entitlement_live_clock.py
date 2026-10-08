"""Prevent time drift between issuing a grant and checking RLS visibility."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "control-plane" / "supabase" / "migrations" /
       "20261007210000_entitlement_rls_live_clock_v1.sql")


class EntitlementLiveClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_live_clock_and_original_owner_boundary(self):
        s = self.sql
        self.assertIn("alter policy ordax_entitlement_grants_select_subject", s)
        self.assertIn("valid_from<=pg_catalog.clock_timestamp()", s)
        self.assertIn("valid_until>pg_catalog.clock_timestamp()", s)
        self.assertIn("user_id=(select auth.uid())", s)
        self.assertIn("private.ordax_can_access_space(space_id)", s)
        self.assertIn("v_policy like '%statement_timestamp%'", s)
        self.assertNotIn("create policy", s)
        self.assertNotIn("grant execute", s)
        self.assertNotIn("create role", s)


if __name__ == "__main__":
    unittest.main()
