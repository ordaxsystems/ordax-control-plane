from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
LEGACY_REVIEW_WORKFLOW = WORKFLOWS / "openai-review-grant.yml"


class OpenAiReviewGrantWorkflowTests(unittest.TestCase):
    def test_legacy_review_grant_workflow_is_removed(self) -> None:
        self.assertFalse(
            LEGACY_REVIEW_WORKFLOW.exists(),
            "legacy review grant workflow must not be reintroduced",
        )

    def test_workflows_do_not_reintroduce_legacy_operator_authority(self) -> None:
        workflow_text = "\n".join(
            path.read_text(encoding="utf-8")
            for pattern in ("*.yml", "*.yaml")
            for path in sorted(WORKFLOWS.glob(pattern))
        )
        self.assertNotIn("ordax-ac1ca1b50d09", workflow_text)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", workflow_text)
        self.assertNotIn("/v3/product-grants/from-link", workflow_text)


if __name__ == "__main__":
    unittest.main()
