#!/usr/bin/env python3
"""Black-box contract tests for the campaign coordinator command."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "campaign_coordinator.py"
LEAD_CLI = ROOT / "scripts" / "lead_state.py"


class CampaignCoordinatorCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.engagement = Path(self.temporary.name) / "synthetic-engagement"
        self.engagement.mkdir()

    def run_json_command(
        self, command: list[str], *, expected: int = 0
    ) -> dict[str, object]:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def run_cli(
        self, *, event: dict[str, object] | None = None, expected: int = 0
    ) -> dict[str, object]:
        command = [
            sys.executable,
            str(CLI),
            "--engagement",
            str(self.engagement),
        ]
        if event is not None:
            command.extend(("--event", json.dumps(event)))
        return self.run_json_command(command, expected=expected)

    def run_lead_cli(self, *args: str) -> dict[str, object]:
        return self.run_json_command(
            [
                sys.executable,
                str(LEAD_CLI),
                "--engagement",
                str(self.engagement),
                *args,
            ]
        )

    def test_opens_a_new_engagement_with_durable_normalized_state(self) -> None:
        response = self.run_cli()

        self.assertEqual(response["schema_version"], 1)
        self.assertIsNone(response["event"])
        self.assertIsNone(response["next_work"])
        self.assertEqual(
            response["completion"],
            {
                "actionable": 0,
                "outcome": "incomplete",
                "reasons": ["coverage_empty"],
            },
        )
        state = response["state"]
        self.assertIsInstance(state, dict)
        self.assertEqual(state["schema_version"], 1)
        self.assertEqual(state["leads"], [])
        state_path = self.engagement / "state" / "lead-state.json"
        self.assertTrue(state_path.is_file())
        self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), state)

    def test_reopening_unchanged_state_is_deterministic_and_read_only(self) -> None:
        first = self.run_cli()
        second = self.run_cli()

        self.assertEqual(second, first)

    def test_opens_existing_v1_state_and_returns_highest_priority_work(self) -> None:
        lower = self.run_lead_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "surface-inventory",
                    "kind": "endpoint",
                    "subject": "https://synthetic.example.test/lower",
                    "priority": 30,
                    "provenance": ["fixture:v1"],
                    "evidence": [],
                }
            ),
        )["lead"]
        higher = self.run_lead_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "access-control",
                    "kind": "endpoint",
                    "subject": "https://synthetic.example.test/higher",
                    "priority": 80,
                    "provenance": ["fixture:v1"],
                    "evidence": [],
                }
            ),
        )["lead"]

        response = self.run_cli()

        self.assertEqual(response["next_work"]["id"], higher["id"])
        self.assertEqual(response["next_work"]["status"], "queued")
        self.assertNotEqual(response["next_work"]["id"], lower["id"])
        self.assertEqual(
            response["completion"],
            {
                "actionable": 2,
                "outcome": "incomplete",
                "reasons": ["coverage_empty", "actionable_leads"],
            },
        )
        persisted = json.loads(
            (self.engagement / "state" / "lead-state.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(response["state"], persisted)
        self.assertTrue(all(lead["status"] == "queued" for lead in persisted["leads"]))

    def test_applies_a_synthetic_event_and_returns_the_resulting_frontier(self) -> None:
        response = self.run_cli(
            event={
                "schema_version": 1,
                "type": "lead.upsert",
                "payload": {
                    "lead": {
                        "family": "auth-session",
                        "kind": "endpoint",
                        "subject": "https://synthetic.example.test/session",
                        "method": "POST",
                        "priority": 70,
                        "provenance": ["event:synthetic"],
                        "evidence": ["fixture:observation"],
                        "hypothesis": "The session transition may retain stale authority.",
                    }
                },
            }
        )

        applied = response["event"]
        self.assertEqual(applied["schema_version"], 1)
        self.assertEqual(applied["type"], "lead.upsert")
        self.assertEqual(applied["result"]["result"], "appended")
        lead = applied["result"]["lead"]
        self.assertEqual(response["next_work"]["id"], lead["id"])
        self.assertEqual(response["completion"]["outcome"], "incomplete")
        self.assertEqual(response["completion"]["actionable"], 1)
        state_path = self.engagement / "state" / "lead-state.json"
        self.assertEqual(
            json.loads(state_path.read_text(encoding="utf-8")), response["state"]
        )

        reopened = self.run_cli()
        self.assertIsNone(reopened["event"])
        self.assertEqual(len(reopened["state"]["leads"]), 1)
        self.assertEqual(reopened["next_work"]["id"], lead["id"])

    def test_budget_exhaustion_returns_no_eligible_work(self) -> None:
        self.run_lead_cli("configure", "--max-iterations", "1")
        self.run_lead_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "surface-inventory",
                    "kind": "endpoint",
                    "subject": "https://synthetic.example.test/queued-after-budget",
                    "priority": 90,
                    "provenance": ["fixture:budget"],
                    "evidence": [],
                }
            ),
        )
        self.run_lead_cli("iteration", "--no-progress")

        response = self.run_cli()

        self.assertEqual(response["completion"]["outcome"], "budget_exhausted")
        self.assertEqual(
            response["completion"]["reasons"], ["iteration_budget_exhausted"]
        )
        self.assertIsNone(response["next_work"])


if __name__ == "__main__":
    unittest.main()
