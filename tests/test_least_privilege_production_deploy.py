from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LeastPrivilegeProductionDeployTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/cloudflare-v3-deploy.yml").read_text(encoding="utf-8")
        cls.deploy = (ROOT / "scripts/cloudflare/deploy-production-v3.sh").read_text(encoding="utf-8")
        cls.wrangler = (ROOT / "control-plane/cloudflare/wrangler.toml").read_text(encoding="utf-8")

    def test_routine_workflow_requires_only_cloudflare_deploy_token(self) -> None:
        self.assertIn("CLOUDFLARE_API_TOKEN", self.workflow)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", self.workflow)
        self.assertNotIn("verify_cloudflare_v3.py", self.workflow)
        self.assertIn("verify_cloudflare_public.py", self.workflow)

    def test_routine_deploy_does_not_provision_bound_infrastructure(self) -> None:
        for forbidden in (
            "d1 create",
            "d1 migrations apply",
            "r2 bucket create",
            "secret put",
            "--secrets-file",
        ):
            self.assertNotIn(forbidden, self.deploy)
        self.assertIn('wrangler@${WRANGLER_VERSION}" deploy', self.deploy)

    def test_canonical_config_has_production_bindings_and_auth(self) -> None:
        self.assertIn('database_id = "ac121be2-0459-47f9-abb7-1033c60c52c0"', self.wrangler)
        self.assertNotIn("REPLACE_WITH_D1_DATABASE_ID", self.wrangler)
        self.assertIn('bucket_name = "ordax-device-artifacts"', self.wrangler)
        self.assertIn('PRODUCT_AUTH_AUDIENCE = "authenticated"', self.wrangler)

    def test_privileged_bootstrap_is_not_the_routine_workflow(self) -> None:
        self.assertNotIn("scripts/cloudflare/deploy-v3.sh", self.workflow)
        bootstrap = (ROOT / "scripts/cloudflare/deploy-v3.sh").read_text(encoding="utf-8")
        self.assertIn("BOOTSTRAP / INFRASTRUCTURE MIGRATION ONLY", bootstrap)


if __name__ == "__main__":
    unittest.main()
