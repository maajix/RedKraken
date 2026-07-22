#!/usr/bin/env python3
"""Tests for path-first, read-only engagement hygiene inventory."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "audit_engagement_hygiene.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_engagement_hygiene", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EngagementHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "sample"
        (self.root / "state").mkdir(parents=True)
        (self.root / "evidence" / "F-001").mkdir(parents=True)
        (self.root / "engagement.yaml").write_text(
            "targets:\n  - 203.0.113.44\n  - '*.cloud.example'\n"
            "out_of_scope:\n  - 198.51.100.0/24\n"
            "retention:\n  status: expired\n  owner: security@example.test\n"
        )
        (self.root / "state" / "findings.jsonl").write_text(json.dumps({
            "id": "F-001", "evidence": ["evidence/F-001/request.txt"],
        }) + "\n")
        (self.root / "evidence" / "F-001" / "request.txt").write_text("safe evidence")
        self.secret = "fixture-password-never-print"
        (self.root / "state" / "synthetic-credentials.txt").write_text(
            f"password={self.secret}\n"
        )
        os.chmod(self.root, 0o755)
        os.chmod(self.root / "state" / "synthetic-credentials.txt", 0o644)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def report(self):
        return load_module().audit_engagement(self.root)

    def test_output_never_contains_secret_values(self) -> None:
        module = load_module()
        stream = io.StringIO()
        with redirect_stdout(stream):
            module.emit_report(module.audit_engagement(self.root), json_output=True)
        rendered = stream.getvalue()
        self.assertNotIn(self.secret, rendered)
        parsed = json.loads(rendered)
        secret_row = next(row for row in parsed["files"] if row["path"].endswith("synthetic-credentials.txt"))
        self.assertEqual(secret_row["class"], "D")
        self.assertEqual(secret_row["action"], "delete")
        self.assertEqual(secret_row["value_sha256"], "")
        self.assertRegex(secret_row["sha256"], r"^[0-9a-f]{64}$")

    def test_network_identifiers_and_referenced_evidence_are_preserved(self) -> None:
        report = self.report()
        self.assertEqual(
            set(report["preservation_set"]["network_identifiers"]),
            {"203.0.113.44", "*.cloud.example", "198.51.100.0/24"},
        )
        evidence = next(row for row in report["files"] if row["path"].endswith("request.txt"))
        self.assertEqual(evidence["class"], "C")
        self.assertEqual(evidence["action"], "preserve")
        self.assertGreater(evidence["reference_count"], 0)

    def test_symlinks_are_reported_and_not_followed(self) -> None:
        outside = Path(self.temp.name) / "outside-secret.txt"
        outside.write_text(self.secret)
        (self.root / "state" / "linked.txt").symlink_to(outside)
        report = self.report()
        link = next(row for row in report["files"] if row["path"].endswith("linked.txt"))
        self.assertTrue(link["symlink"])
        self.assertEqual(link["action"], "preserve")
        self.assertNotIn(self.secret, json.dumps(report))

    def test_permissions_are_reported_without_mutation(self) -> None:
        before = stat.S_IMODE(self.root.stat().st_mode)
        report = self.report()
        self.assertEqual(before, stat.S_IMODE(self.root.stat().st_mode))
        self.assertFalse(report["permissions"]["directory_secure"])
        row = next(row for row in report["files"] if row["path"].endswith("synthetic-credentials.txt"))
        self.assertEqual(row["mode"], "0644")
        self.assertFalse(row["permission_secure"])

    def test_malformed_config_blocks_deletion(self) -> None:
        (self.root / "engagement.yaml").write_text("targets: [\n")
        report = self.report()
        self.assertTrue(report["deletion_blocked"])
        self.assertTrue(all(row["action"] != "delete" for row in report["files"]))

    def test_scratch_and_engagement_helpers_have_distinct_lifecycle_actions(self) -> None:
        (self.root / "state" / "scratch").mkdir()
        (self.root / "state" / "scripts").mkdir()
        (self.root / "state" / "scratch" / "throwaway.py").write_text("print('local')\n")
        (self.root / "state" / "scripts" / "normalize.py").write_text("print('local')\n")
        rows = {row["path"]: row for row in self.report()["files"]}
        self.assertEqual(rows["state/scratch/throwaway.py"]["action"], "delete")
        self.assertEqual(
            rows["state/scripts/normalize.py"]["action"], "review-for-promotion"
        )

    def test_only_gitkeep_is_tracked_under_engagements(self) -> None:
        module = load_module()
        self.assertLessEqual(module.tracked_engagement_paths(ROOT), {"engagements/.gitkeep"})

    def test_repo_state_distinguishes_tracked_ignored_and_external(self) -> None:
        module = load_module()
        self.assertEqual(module.repo_state(ROOT / "README.md", ROOT), "tracked")
        self.assertEqual(
            module.repo_state(
                ROOT / "engagements" / "synthetic-hygiene-fixture" / "engagement.yaml",
                ROOT,
            ),
            "ignored",
        )
        self.assertEqual(module.repo_state(self.root / "engagement.yaml", ROOT), "external")


if __name__ == "__main__":
    unittest.main()
