#!/usr/bin/env python3
"""Synthetic integration tests for durable engagement phase transitions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "lib" / "run_context.py"
ACTIVE = ROOT / ".active_engagement"


class RunContextPhaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.engagement = Path(self.temporary.name) / "synthetic-engagement"
        self.engagement.mkdir()
        self.write_engagement("app.synthetic.example.test")
        self.active_before = ACTIVE.read_bytes() if ACTIVE.exists() else None
        self.addCleanup(self.restore_active_pointer)

    def restore_active_pointer(self) -> None:
        if self.active_before is None:
            ACTIVE.unlink(missing_ok=True)
            return
        ACTIVE.write_bytes(self.active_before)
        os.chmod(ACTIVE, 0o600)

    def write_engagement(self, target: str) -> None:
        (self.engagement / "engagement.yaml").write_text(
            "\n".join(
                (
                    "name: synthetic",
                    "targets:",
                    f"  - {target}",
                    "out_of_scope: []",
                    "intent: Authorized synthetic integration fixture.",
                    "mutation_allowed: false",
                    "sensitive_data_access_allowed: false",
                    "credential_use_allowed: false",
                    "pivoting_allowed: false",
                    "availability_impact_allowed: false",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def run_context(self, mode: str, *, expected: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(CLI), str(self.engagement), "--mode", mode],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return result

    def read_run(self) -> dict[str, object]:
        return json.loads(
            (self.engagement / "state" / "run.json").read_text(encoding="utf-8")
        )

    def test_recon_pentest_and_report_share_one_durable_identity(self) -> None:
        self.assertIn("NEW_RUN", self.run_context("recon").stdout)
        initial = self.read_run()
        for relative in ("scan-raw", "scripts", "scratch"):
            path = self.engagement / "state" / relative
            self.assertTrue(path.is_dir(), relative)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

        self.assertIn("RESUME", self.run_context("pentest").stdout)
        self.assertIn("RESUME", self.run_context("report").stdout)
        resumed = self.read_run()

        self.assertEqual(resumed["schema_version"], 2)
        self.assertEqual(resumed["run_id"], initial["run_id"])
        self.assertEqual(resumed["context_sha256"], initial["context_sha256"])
        self.assertEqual(resumed["current_phase"], "report")
        self.assertEqual(
            [entry["phase"] for entry in resumed["phase_history"]],
            ["recon", "pentest", "report"],
        )

    def test_legacy_v1_run_context_migrates_without_being_stale(self) -> None:
        # A pre-phase-model run.json is schema_version 1 with a mode-dependent identity.
        # A later phase must migrate it to v2 in place, not fail closed as stale.
        sys.path.insert(0, str(ROOT / "lib"))
        import run_context  # noqa: PLC0415
        from harness_config import engagement_yaml, load_engagement  # noqa: PLC0415

        yaml_path = engagement_yaml(str(self.engagement))
        config = load_engagement(yaml_path)
        legacy = run_context.legacy_identity_payload(yaml_path, config, "recon")
        state = self.engagement / "state"
        state.mkdir(parents=True, exist_ok=True)
        (state / "run.json").write_text(
            json.dumps(
                {
                    **legacy,
                    "schema_version": 1,
                    "run_id": "legacy-run-id",
                    "started_at": "2026-01-01T00:00:00Z",
                    "last_verified": "2026-01-01T00:00:00Z",
                    "tool_paths": {},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        self.assertIn("RESUME", self.run_context("pentest").stdout)

        migrated = self.read_run()
        self.assertEqual(migrated["schema_version"], 2)
        self.assertNotIn("mode", migrated)
        self.assertEqual(migrated["run_id"], "legacy-run-id")
        self.assertEqual(migrated["current_phase"], "pentest")
        self.assertEqual(
            migrated["context_sha256"],
            run_context.identity_payload(yaml_path, config)["context_sha256"],
        )

    def test_full_pentest_has_a_distinct_guardable_phase(self) -> None:
        self.assertIn("NEW_RUN", self.run_context("full-pentest").stdout)
        self.assertEqual(self.read_run()["current_phase"], "full-pentest")
        self.assertIn("RESUME", self.run_context("report").stdout)

    def test_scope_change_still_fails_closed_across_phase_transition(self) -> None:
        self.run_context("recon")
        before = self.read_run()
        self.write_engagement("changed.synthetic.example.test")

        result = self.run_context("pentest", expected=3)

        self.assertIn("STALE_RUN_CONTEXT", result.stderr)
        self.assertEqual(self.read_run(), before)


if __name__ == "__main__":
    unittest.main()
