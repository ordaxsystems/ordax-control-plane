import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "configure-control-plane-secrets.ps1"


class SecureSecretCutoverScriptTests(unittest.TestCase):
    def test_script_never_prints_or_embeds_secret_values(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("Write-Output $cloudflareToken", text)
        self.assertIn(
            'Read-Host "Cloudflare Worker deploy API token (input hidden)" -AsSecureString',
            text,
        )
        self.assertIn("ZeroFreeBSTR", text)

    def test_helper_configures_only_the_routine_deploy_credential(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("CLOUDFLARE_API_TOKEN", text)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", text)
        self.assertNotIn("RandomNumberGenerator", text)
        self.assertIn("ORDAX_CONTROL_PLANE_DEPLOY_SECRET=READY", text)

    def test_helper_targets_protected_cloudflare_environment(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('$Environment = "cloudflare-v3"', text)
        self.assertIn("gh secret set CLOUDFLARE_API_TOKEN", text)
        self.assertIn("--env $Environment", text)


if __name__ == "__main__":
    unittest.main()
