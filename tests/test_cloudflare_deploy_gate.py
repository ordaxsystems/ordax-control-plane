import copy
import importlib.util
import json
import os
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/cloudflare/check_deploy_readiness.py"
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.toml"
LEGACY = ROOT / "scripts/cloudflare/deploy-v3.sh"
ROUTINE = ROOT / "scripts/cloudflare/deploy-production-v3.sh"

spec = importlib.util.spec_from_file_location("ordax_cloudflare_deploy_gate", GUARD)
gate = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(gate)


class CloudflareDirectDeployGateTests(unittest.TestCase):
    def setUp(self):
        self.foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as stream:
            self.wrangler = tomllib.load(stream)

    def validate(self, source="export default {}"):
        return gate.validate(self.foundation, self.wrangler, source,
                             self.foundation["account_id"])

    def test_existing_foundation_is_blocked(self):
        self.assertFalse(self.validate())
        self.assertIn("worker_d1_cutover_incomplete", self.foundation["readiness_blockers"])

    def test_ready_foundation_requires_no_d1_binding(self):
        self.foundation["deployment_ready"] = True
        self.foundation["readiness_blockers"] = []
        with self.assertRaisesRegex(gate.DeployGateError, "D1 binding"):
            self.validate()

    def test_ready_foundation_requires_no_operator_or_d1_source(self):
        self.foundation["deployment_ready"] = True
        self.foundation["readiness_blockers"] = []
        self.wrangler.pop("d1_databases", None)
        with self.assertRaisesRegex(gate.DeployGateError, "D1 access"):
            self.validate("async function x() { return env.DB.prepare('select 1'); }")
        with self.assertRaisesRegex(gate.DeployGateError, "operator bearer"):
            self.validate("return operatorAuthorized(request, env);")
        with self.assertRaisesRegex(gate.DeployGateError, "Supabase server secret"):
            self.validate("const SUPABASE_SERVER_KEY = 'forbidden';")
        self.assertTrue(self.validate("export default {}"))

    def test_forged_readiness_or_missing_blockers_fails_closed(self):
        self.foundation["deployment_ready"] = True
        with self.assertRaisesRegex(gate.DeployGateError, "contradicts"):
            self.validate()
        self.foundation["deployment_ready"] = False
        self.foundation["readiness_blockers"] = []
        with self.assertRaisesRegex(gate.DeployGateError, "contradicts"):
            self.validate()

    def test_canonical_binding_and_account_are_enforced(self):
        with self.assertRaisesRegex(gate.DeployGateError, "account differs"):
            gate.validate(self.foundation, self.wrangler, "", "0" * 32)
        self.wrangler["hyperdrive"][0]["id"] = "0" * 32
        with self.assertRaisesRegex(gate.DeployGateError, "Hyperdrive binding"):
            self.validate()

    def test_do_and_r2_bindings_are_enforced(self):
        self.wrangler["r2_buckets"][0]["bucket_name"] = "incorrect"
        with self.assertRaisesRegex(gate.DeployGateError, "R2 bucket"):
            self.validate()
        self.wrangler["r2_buckets"][0]["bucket_name"] = self.foundation["r2_bucket"]
        self.wrangler["durable_objects"]["bindings"][0]["class_name"] = "Changed"
        with self.assertRaisesRegex(gate.DeployGateError, "Durable Objects"):
            self.validate()

    def test_direct_guard_rejects_actual_not_ready_foundation(self):
        env = {**os.environ, "CLOUDFLARE_ACCOUNT_ID": self.foundation["account_id"]}
        command = [sys.executable, str(GUARD)]
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("BLOCKED", result.stdout)
        preview = subprocess.run(command + ["--allow-blocked"], cwd=ROOT,
                                 env=env, capture_output=True, text=True)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("BLOCKED", preview.stdout)

    def test_retired_bootstrap_exits_without_deploy_credentials(self):
        result = subprocess.run(["bash", str(LEGACY)], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 3)
        self.assertIn("retired", result.stderr)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", result.stderr)


if __name__ == "__main__":
    unittest.main()
