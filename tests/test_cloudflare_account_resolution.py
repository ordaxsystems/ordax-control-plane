import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-v3-deploy.yml"
DEPLOY = ROOT / "scripts" / "cloudflare" / "deploy-v3.sh"

class CloudflareAccountResolutionContractTests(unittest.TestCase):
    def test_account_id_is_not_required_as_github_secret(self):
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertNotIn("secrets.CLOUDFLARE_ACCOUNT_ID", workflow)
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", workflow)
        self.assertIn("secrets.ORDAX_OPERATOR_TOKEN", workflow)

    def test_deploy_resolves_single_account_fail_closed(self):
        script = DEPLOY.read_text(encoding="utf-8")
        self.assertIn("/client/v4/accounts?per_page=50", script)
        self.assertIn("len(ids) != 1", script)
        self.assertIn("set CLOUDFLARE_ACCOUNT_ID explicitly", script)
        self.assertNotIn("CLOUDFLARE_ACCOUNT_ID is required", script)

if __name__ == "__main__":
    unittest.main()
