import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-v3-deploy.yml"
BOOTSTRAP = ROOT / "scripts" / "cloudflare" / "deploy-v3.sh"


class CloudflareAccountResolutionContractTests(unittest.TestCase):
    def test_routine_deploy_uses_explicit_non_secret_account_id(self):
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertNotIn("secrets.CLOUDFLARE_ACCOUNT_ID", workflow)
        self.assertIn(
            "CLOUDFLARE_ACCOUNT_ID: ac1ca1b50d09c7a4cb81274d2aa1e78f",
            workflow,
        )
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("secrets.ORDAX_OPERATOR_TOKEN", workflow)

    def test_privileged_bootstrap_can_still_resolve_account_fail_closed(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("/client/v4/accounts?per_page=50", script)
        self.assertIn("len(ids) != 1", script)
        self.assertIn("set CLOUDFLARE_ACCOUNT_ID explicitly", script)
        self.assertNotIn("CLOUDFLARE_ACCOUNT_ID is required", script)


if __name__ == "__main__":
    unittest.main()
