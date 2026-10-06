import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "configure-control-plane-secrets.ps1"

class SecureSecretCutoverScriptTests(unittest.TestCase):
    def test_script_never_prints_secret_values(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('Write-Output $cloudflareToken', text)
        self.assertNotIn('Write-Output $operatorToken', text)
        self.assertIn('Read-Host "Cloudflare API token (input hidden)" -AsSecureString', text)

    def test_operator_token_is_generated_cryptographically(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("RandomNumberGenerator", text)
        self.assertIn("CLOUDFLARE_API_TOKEN", text)
        self.assertIn("ORDAX_OPERATOR_TOKEN", text)
        self.assertIn("ORDAX_CONTROL_PLANE_SECRETS=READY", text)

if __name__ == "__main__":
    unittest.main()
