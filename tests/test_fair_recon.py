#!/usr/bin/env python3
"""Deterministic black-box tests for fair reconnaissance scheduling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "scripts" / "campaign_coordinator.py"
LEADS = ROOT / "scripts" / "lead_state.py"


class FairReconTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.engagement = Path(self.temporary.name) / "synthetic-engagement"
        self.engagement.mkdir()
        (self.engagement / "engagement.yaml").write_text(
            "\n".join(
                (
                    "name: synthetic",
                    "targets:",
                    "  - first.synthetic.example.test",
                    "  - second.synthetic.example.test",
                    "out_of_scope: []",
                    "intent: Authorized synthetic fairness fixture.",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def run_json(self, command: list[str]) -> dict[str, object]:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def coordinator(self) -> dict[str, object]:
        return self.run_json(
            [sys.executable, str(COORDINATOR), "--engagement", str(self.engagement)]
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

    def test_baseline_work_preempts_depth_and_rotates_to_untouched_asset(self) -> None:
        opened = self.coordinator()
        first_work = opened["next_work"]
        self.assertEqual(first_work["kind"], "discovery")

        number = 0
        while True:
            subject = f"https://{first_work['subject']}/depth/{number}"
            identity = {
                "family": "access-control",
                "kind": "endpoint",
                "subject": subject,
                "method": "GET",
                "parameter": "",
            }
            candidate_id = "L-" + hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()[:16]
            if candidate_id < first_work["id"]:
                break
            number += 1
        smallest_depth = self.lead_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "access-control",
                    "kind": "endpoint",
                    "subject": subject,
                    "priority": 100,
                    "provenance": ["fixture:deep-lead"],
                    "evidence": [],
                }
            ),
        )["lead"]
        self.assertEqual(smallest_depth["id"], candidate_id)

        still_baseline = self.coordinator()["next_work"]
        self.assertEqual(still_baseline["kind"], "discovery")
        served_asset = still_baseline["subject"]
        self.lead_cli(
            "lease", still_baseline["id"], "--worker", "fixture-worker"
        )
        self.lead_cli(
            "complete",
            still_baseline["id"],
            "--worker",
            "fixture-worker",
            "--outcome",
            "completed",
        )
        self.lead_cli(
            "coverage",
            "--dimension",
            "workflow",
            "--key",
            (
                f"asset={still_baseline['subject']};method={still_baseline['method'].lower()};"
                f"role={still_baseline['parameter']}"
            ),
            "--status",
            "tested",
        )

        next_work = self.coordinator()["next_work"]
        self.assertEqual(next_work["kind"], "discovery")
        self.assertNotEqual(next_work["subject"], served_asset)

    def test_no_progress_is_scoped_to_one_asset_method(self) -> None:
        opened = self.coordinator()
        rows = opened["state"]["coverage"]
        first_key = next(
            row["key"]
            for row in rows
            if row["key"].startswith("asset=first.")
            and ";method=crawl;" in row["key"]
        )
        second_key = first_key.replace("asset=first.", "asset=second.")

        self.lead_cli(
            "coverage",
            "--dimension",
            "workflow",
            "--key",
            first_key,
            "--status",
            "exhausted",
            "--reason",
            "no progress for this asset-method lane",
        )
        response = self.coordinator()
        coverage = {row["key"]: row for row in response["state"]["coverage"]}

        self.assertEqual(coverage[first_key]["status"], "exhausted")
        self.assertEqual(coverage[second_key]["status"], "not-tested")
        self.assertEqual(response["completion"]["outcome"], "incomplete")


if __name__ == "__main__":
    unittest.main()
