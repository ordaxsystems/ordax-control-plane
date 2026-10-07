import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "contracts" / "repository-migration.json"


class RepositoryNamespaceMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_transfer_target_is_exact_and_identity_preserving(self):
        self.assertEqual(
            self.contract["$schema"],
            "ordax-control-plane.repository-migration/1",
        )
        self.assertEqual(\n            self.contract["status"],\n            "owner-transfer-complete-validation-pending",\n        )
        self.assertEqual(self.contract["repository_id"], "1406415892")
        self.assertEqual(
            self.contract["previous_repository"],
            "washingtonmsdj/ordax-control-plane",
        )
        self.assertEqual(
            self.contract["canonical_repository"],
            "ordaxsystems/ordax-control-plane",
        )
        self.assertFalse(self.contract["repository_name_changes_during_transfer"])
        self.assertEqual(
            self.contract["transfer_observed"],
            {
                "repository_id": "1406415892",
                "owner": "ordaxsystems",
                "repository": "ordax-control-plane",
            },
        )

    def test_cutover_keeps_single_authority(self):
        self.assertFalse(self.contract["redirect_dependency_allowed"])
        self.assertFalse(self.contract["mirror_repository_allowed"])
        self.assertFalse(self.contract["dual_authority_allowed"])
        self.assertFalse(self.contract["provenance_rewrite_allowed"])
        self.assertTrue(self.contract["transfer_first_then_repoint"])
        self.assertTrue(self.contract["production_mutation_during_transfer_forbidden"])

    def test_platform_authorities_do_not_move_with_git_owner(self):
        owners = self.contract["invariant_owners"]
        self.assertEqual(owners["persistent_authority"], "postgresql")
        self.assertEqual(owners["artifact_authority"], "r2")
        self.assertEqual(
            owners["realtime_session_coordination"],
            "durable_objects",
        )
        self.assertEqual(owners["remote_control_plane"], "ordax-control-plane")

    def test_post_transfer_revalidation_is_mandatory(self):
        completed = set(self.contract["completed_requirements"])
        pending = set(self.contract["pending_requirements"])
        self.assertIn("repository-transfer-complete", completed)
        self.assertIn("control-plane-ci-green-after-transfer", pending)
        self.assertIn(
            "github-environments-and-deploy-credentials-revalidated",
            pending,
        )
        self.assertIn("consumer-references-repointed", pending)


if __name__ == "__main__":
    unittest.main()
