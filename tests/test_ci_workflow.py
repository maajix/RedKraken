#!/usr/bin/env python3
"""Keep CI pointed at maintained, repository-local coverage gates."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


class CiWorkflowTest(unittest.TestCase):
    def test_coverage_jobs_do_not_call_removed_script(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("scripts/check_coverage.sh", workflow)
        self.assertIn("python3 scripts/rebuild_catalog.py", workflow)
        self.assertIn("bash tests/test_playbook_coverage.sh", workflow)

    def test_completion_guard_regression_test_runs_in_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("python3 tests/test_completion_guard.py", workflow)

    def test_scope_proxy_regression_test_runs_in_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("python3 tests/test_scope_proxy.py", workflow)

    def test_scope_guard_deny_path_and_roe_policy_run_in_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("python3 tests/test_scope_guard_block.py", workflow)
        self.assertIn("python3 tests/test_roe_policy.py", workflow)
        self.assertIn("bash tests/test_vhost_discovery.sh", workflow)


if __name__ == "__main__":
    unittest.main()
