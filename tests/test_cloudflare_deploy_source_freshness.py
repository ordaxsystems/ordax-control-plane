from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRESHNESS = ROOT / "scripts/cloudflare/assert-current-main.sh"
ROUTINE = ROOT / "scripts/cloudflare/deploy-production-v3.sh"
BOOTSTRAP = ROOT / "scripts/cloudflare/bootstrap-worker-v3.sh"
WORKFLOW = ROOT / ".github/workflows/cloudflare-v3-deploy.yml"


def run_git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


class CloudflareMainSourceFreshnessTests(unittest.TestCase):
    def test_current_main_only_and_remote_fetch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "origin.git"
            checkout = root / "checkout"
            bare.mkdir()
            checkout.mkdir()
            run_git("init", "--bare", str(bare), cwd=root)
            run_git("init", cwd=checkout)
            run_git("config", "user.email", "ci@example.invalid", cwd=checkout)
            run_git("config", "user.name", "CI Test", cwd=checkout)
            run_git("commit", "--allow-empty", "-m", "initial", cwd=checkout)
            run_git("branch", "-M", "main", cwd=checkout)
            run_git("remote", "add", "origin", str(bare), cwd=checkout)
            run_git("push", "-u", "origin", "main", cwd=checkout)

            def verify() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(FRESHNESS), str(checkout)],
                    cwd=root, capture_output=True, text=True, check=False,
                )

            good = verify()
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn("matches current remote main", good.stdout)

            run_git("commit", "--allow-empty", "-m", "local ahead", cwd=checkout)
            ahead = verify()
            self.assertEqual(ahead.returncode, 4)
            self.assertIn("stale", ahead.stderr)

            run_git("push", "origin", "main", cwd=checkout)
            self.assertEqual(verify().returncode, 0)

            run_git("reset", "--hard", "HEAD~1", cwd=checkout)
            behind = verify()
            self.assertEqual(behind.returncode, 4)
            self.assertIn("stale", behind.stderr)

            run_git("remote", "set-url", "origin", str(root / "missing.git"), cwd=checkout)
            unavailable = verify()
            self.assertEqual(unavailable.returncode, 4)
            self.assertIn("Cannot verify current remote main", unavailable.stderr)

    def test_all_worker_publication_paths_require_fresh_source_before_tokens(self) -> None:
        for script in (ROUTINE, BOOTSTRAP):
            content = script.read_text(encoding="utf-8")
            self.assertIn('bash "$ROOT/scripts/cloudflare/assert-current-main.sh" "$ROOT"', content)
            self.assertLess(
                content.index("check_deploy_readiness.py"),
                content.index("assert-current-main.sh"),
            )
            self.assertLess(
                content.index("assert-current-main.sh"),
                content.index("CLOUDFLARE_API_TOKEN:?"),
            )
        self.assertNotIn("CLOUDFLARE_API_TOKEN", FRESHNESS.read_text(encoding="utf-8"))

    def test_deploy_workflow_rejects_foreign_ci_and_non_main_manual_dispatch(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.event.workflow_run.head_repository.full_name == github.repository", workflow)
        self.assertIn("github.event.workflow_run.head_branch == 'main'", workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertIn("github.event.workflow_run.head_sha", workflow)


if __name__ == "__main__":
    unittest.main()
