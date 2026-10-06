from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "control-plane" / "cloudflare" / "src" / "product_intelligence_grants.ts"
SCOPE = ROOT / "control-plane" / "cloudflare" / "src" / "product_action_scope.ts"
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"


class OwnerDeviceIntelligenceGrantContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.handler = HANDLER.read_text(encoding="utf-8")
        cls.scope = SCOPE.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")

    def test_profile_is_fixed_and_server_derived(self) -> None:
        self.assertIn('APP_INTELLIGENCE_READ_MODE = "app-intelligence-read"', self.handler)
        self.assertIn("[...APP_INTELLIGENCE_DEVICE_ACTIONS].sort()", self.handler)
        self.assertIn("authenticateProductRequest(request, env)", self.handler)
        self.assertIn("linkedDeviceForOwner(env, identity.subjectId, linkId)", self.handler)
        self.assertNotIn("body.actions", self.handler)
        self.assertNotIn("body.projects", self.handler)
        self.assertNotIn("body.project", self.handler)
        self.assertNotIn("body.subject_id", self.handler)
        self.assertNotIn("body.device_id", self.handler)
        self.assertNotIn("body.space_id", self.handler)

    def test_profile_contains_only_read_only_app_intelligence_actions(self) -> None:
        self.assertIn('"intelligence.app_catalog"', self.scope)
        self.assertIn('"intelligence.app_detail"', self.scope)
        self.assertNotIn('"computer.click"', self.handler)
        self.assertNotIn('"computer.hotkey"', self.handler)
        self.assertNotIn('"browser.start"', self.handler)
        self.assertNotIn('"terminal.exec"', self.handler)

    def test_device_intelligence_grant_has_no_project_scope(self) -> None:
        self.assertIn('const projectsJson = "[]";', self.handler)
        self.assertIn("projects.length !== 0", self.handler)
        self.assertIn("APP_INTELLIGENCE_DEVICE_ACTIONS.has(action)", self.handler)

    def test_owner_route_exists_but_mcp_cannot_mint_or_revoke_grants(self) -> None:
        self.assertIn("/v3/product/device-intelligence-grants", self.worker)
        self.assertIn("createOwnerDeviceIntelligenceGrant", self.worker)
        self.assertIn("listOwnerDeviceIntelligenceGrants", self.worker)
        self.assertIn("revokeOwnerDeviceIntelligenceGrant", self.worker)
        self.assertNotIn("createOwnerDeviceIntelligenceGrant", self.mcp)
        self.assertNotIn("revokeOwnerDeviceIntelligenceGrant", self.mcp)

    def test_mcp_tools_are_read_only_and_use_specific_profile_hint(self) -> None:
        self.assertIn('name: "app_intelligence_catalog"', self.mcp)
        self.assertIn('name: "app_intelligence_detail"', self.mcp)
        self.assertIn('"app_intelligence_catalog"', self.mcp)
        self.assertIn('"app_intelligence_detail"', self.mcp)
        self.assertIn('profile: "app-intelligence-read"', self.mcp)
        self.assertIn(
            'APP_INTELLIGENCE_GRANT_SURFACE = "ORDAX Studio > Inteligência dos apps"',
            self.mcp,
        )

    def test_worker_accepts_intelligence_prefix_only_through_explicit_action_catalog(self) -> None:
        self.assertIn('"intelligence."', self.worker)
        self.assertIn('"intelligence.app_catalog"', self.worker)
        self.assertIn('"intelligence.app_detail"', self.worker)
        self.assertNotIn('action.startsWith("intelligence.")', self.scope)


if __name__ == "__main__":
    unittest.main()
