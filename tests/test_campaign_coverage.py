#!/usr/bin/env python3
"""Black-box tests for required reconnaissance coverage and completion."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "scripts" / "campaign_coordinator.py"
LEADS = ROOT / "scripts" / "lead_state.py"


class CampaignCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.engagement = Path(self.temporary.name) / "synthetic-engagement"
        self.engagement.mkdir()

    def write_engagement(self) -> None:
        (self.engagement / "engagement.yaml").write_text(
            "\n".join(
                (
                    "name: synthetic",
                    "targets:",
                    "  - app.synthetic.example.test",
                    "  - api.synthetic.example.test",
                    "out_of_scope: []",
                    "intent: Authorized synthetic coverage fixture.",
                    "test_credentials:",
                    "  - fixture-user:fixture-secret",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def run_json(self, command: list[str], *, expected: int = 0) -> dict[str, object]:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def coordinator(self) -> dict[str, object]:
        return self.run_json(
            [
                sys.executable,
                str(COORDINATOR),
                "--engagement",
                str(self.engagement),
            ]
        )

    def lead_cli(self, *args: str) -> dict[str, object]:
        return self.run_json(
            [
                sys.executable,
                str(LEADS),
                "--engagement",
                str(self.engagement),
                *args,
            ]
        )

    def test_declared_assets_seed_required_coverage_and_discovery_work(self) -> None:
        self.write_engagement()

        response = self.coordinator()

        coverage = response["state"]["coverage"]
        keys = {entry["key"] for entry in coverage}
        for asset in (
            "app.synthetic.example.test",
            "api.synthetic.example.test",
        ):
            for method in ("dns", "virtual-hosts", "services", "crawl", "api-schema"):
                self.assertIn(f"asset={asset};method={method};role=anonymous", keys)
            self.assertIn(
                f"asset={asset};method=crawl;role=authorized-role-1", keys
            )
        self.assertTrue(all(entry["status"] == "not-tested" for entry in coverage))
        self.assertEqual(len(response["state"]["leads"]), len(coverage))
        self.assertEqual(response["completion"]["outcome"], "incomplete")
        self.assertEqual(response["completion"]["remaining_frontier"], coverage)

    def test_pending_coverage_without_queued_work_is_repaired(self) -> None:
        self.write_engagement()
        first = self.coordinator()
        work = first["next_work"]
        self.lead_cli("lease", work["id"], "--worker", "fixture-worker")
        self.lead_cli(
            "complete",
            work["id"],
            "--worker",
            "fixture-worker",
            "--outcome",
            "completed",
        )

        repaired = self.coordinator()

        lead = next(
            item for item in repaired["state"]["leads"] if item["id"] == work["id"]
        )
        self.assertEqual(lead["status"], "queued")
        self.assertEqual(lead["attempts"], 0)

    def test_blocked_coverage_has_operator_blocked_outcome(self) -> None:
        self.lead_cli(
            "coverage",
            "--dimension",
            "workflow",
            "--key",
            "asset=blocked.synthetic.example.test;method=crawl;role=anonymous",
            "--status",
            "blocked",
            "--reason",
            "operator approval required",
        )

        response = self.coordinator()

        self.assertEqual(response["completion"]["outcome"], "operator_blocked")
        self.assertIsNone(response["next_work"])
        self.assertEqual(len(response["completion"]["remaining_frontier"]), 1)


if __name__ == "__main__":
    unittest.main()
