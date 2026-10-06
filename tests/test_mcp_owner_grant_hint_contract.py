from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"


class McpOwnerGrantHintContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = MCP.read_text(encoding="utf-8")

    def test_grant_failure_remains_fail_closed(self) -> None:
        self.assertIn('createdPayload.error === "product_grant_not_resolved"', self.source)
        self.assertIn('return textToolResult(hint ? { ...createdPayload, ...hint } : createdPayload, true)', self.source)
        self.assertNotIn('createOwnerDeviceComputerGrant', self.source)

    def test_hints_point_only_to_reviewed_owner_profiles(self) -> None:
        for mode in (
            "interactive-computer-control",
            "computer-filesystem",
            "computer-clipboard",
            "computer-process-control",
            "project-browser-automation",
            "app-intelligence-read",
        ):
            self.assertIn(mode, self.source)
        self.assertNotIn('required_owner_profile: "full-computer-control"', self.source)
        self.assertIn('alternative_owner_profile: "full-computer-control"', self.source)
        self.assertIn("alternative_profile_requires_local_full_access: true", self.source)

    def test_sensitive_actions_have_specific_profiles(self) -> None:
        self.assertIn('"computer.terminate_process", { profile: "computer-process-control"', self.source)
        for action in ("computer.clipboard_read", "computer.clipboard_write"):
            self.assertIn(f'"{action}"', self.source)
        for action in ("computer.drag", "computer.hotkey"):
            self.assertIn(f'"{action}"', self.source)

    def test_browser_actions_use_browser_profile_without_computer_authority(self) -> None:
        for action in (
            "browser.start",
            "browser.navigate",
            "browser.snapshot",
            "browser.click",
            "browser.type",
        ):
            self.assertIn(f'"{action}"', self.source)
        self.assertIn('profile: "project-browser-automation"', self.source)
        self.assertIn('BROWSER_GRANT_SURFACE = "ORDAX Studio > Navegador gerenciado"', self.source)

    def test_app_intelligence_actions_use_dedicated_read_profile(self) -> None:
        for action in ("intelligence.app_catalog", "intelligence.app_detail"):
            self.assertIn(f'"{action}"', self.source)
        self.assertIn('profile: "app-intelligence-read"', self.source)
        self.assertIn(
            'APP_INTELLIGENCE_GRANT_SURFACE = "ORDAX Studio > Inteligência de aplicativos"',
            self.source,
        )

    def test_authorization_surface_is_owner_facing_studio(self) -> None:
        self.assertIn('COMPUTER_GRANT_SURFACE = "ORDAX Studio > Acesso ao computador"', self.source)
        self.assertIn('authorization_surface: hint.surface', self.source)
        self.assertIn('authorization_required: true', self.source)


if __name__ == "__main__":
    unittest.main()
