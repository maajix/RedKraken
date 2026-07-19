#!/usr/bin/env python3
"""Deterministic black-box tests for bypass-specialist escalation.

All fixtures are synthetic and live in temporary directories.  The tests never
resolve or contact a real target.
"""

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


class BypassEscalationTests(unittest.TestCase):
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
                    "  - app.synthetic.example.test",
                    "out_of_scope: []",
                    "intent: Authorized synthetic bypass fixture.",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def run_json(self, command: list[str], *, expected: int = 0) -> dict[str, object]:
        result = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        payload = result.stdout if result.stdout.strip() else result.stderr
        return json.loads(payload) if payload.strip() else {}

    def coordinator(self, event: dict[str, object] | None = None) -> dict[str, object]:
        command = [sys.executable, str(COORDINATOR), "--engagement", str(self.engagement)]
        if event is not None:
            command.extend(("--event", json.dumps(event)))
        return self.run_json(command)

    def lead_cli(self, *args: str, expected: int = 0) -> dict[str, object]:
        return self.run_json(
            [sys.executable, str(LEADS), "--engagement", str(self.engagement), *args],
            expected=expected,
        )

    def _original_hypothesis(self) -> str:
        lead = self.lead_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "injection",
                    "kind": "validation",
                    "subject": "https://app.synthetic.example.test/search",
                    "method": "GET",
                    "parameter": "q",
                    "priority": 70,
                    "provenance": ["fixture:hypothesis"],
                    "evidence": ["observation:reflected-quote"],
                    "hypothesis": "Reflected quote may allow SQL injection.",
                }
            ),
        )["lead"]
        return str(lead["id"])

    def _resisted_event(
        self, lead_id: str, *, control: str, authorized: list[str]
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "type": "hypothesis.resisted",
            "payload": {
                "lead_id": lead_id,
                "control": control,
                "standard_techniques": ["percent-encoded quote", "inline comment"],
                "positive_control": "benign payload returns 200",
                "negative_control": "single quote returns 403 at the edge",
                "environment_facts": ["cloud WAF in front", "HTTP/2 downgraded"],
                "authorized_profiles": authorized,
                "safety_requirements": ["respect aggregate rate policy"],
            },
        }

    def test_stable_defense_creates_linked_bypass_assignment(self) -> None:
        original = self._original_hypothesis()
        response = self.coordinator(
            self._resisted_event(
                original,
                control="waf",
                authorized=[
                    "edge-waf",
                    "parser-content-type",
                    "auth-routing",
                    "ratelimit-workflow",
                ],
            )
        )
        result = response["event"]["result"]
        self.assertTrue(result["accepted"])
        self.assertEqual(result["applicable_profiles"], ["edge-waf"])
        self.assertEqual(len(result["scheduled"]), 1)
        scheduled_id = result["scheduled"][0]["lead_id"]

        leads = {lead["id"]: lead for lead in response["state"]["leads"]}
        bypass = leads[scheduled_id]
        self.assertEqual(bypass["kind"], "bypass")
        self.assertEqual(bypass["family"], "bypass-edge-waf")
        self.assertEqual(bypass["parent_leads"], [original])
        self.assertEqual(bypass["subject"], "https://app.synthetic.example.test/search")
        # The assignment carries the observed control, standard techniques,
        # positive/negative controls, environment facts, and safety requirements.
        joined_evidence = "\n".join(bypass["evidence"])
        for fragment in (
            "control:waf",
            "standard:percent-encoded quote",
            "positive-control:",
            "negative-control:",
            "environment:cloud WAF in front",
        ):
            self.assertIn(fragment, joined_evidence)
        self.assertIn("respect aggregate rate policy", bypass["safety_requirements"])

    def test_only_applicable_and_authorized_profiles_are_scheduled(self) -> None:
        original = self._original_hypothesis()
        response = self.coordinator(
            self._resisted_event(
                original, control="waf", authorized=["parser-content-type"]
            )
        )
        result = response["event"]["result"]
        self.assertFalse(result["accepted"])
        self.assertEqual(result["applicable_profiles"], ["edge-waf"])
        self.assertEqual(result["scheduled"], [])
        self.assertEqual(
            [row["profile"] for row in result["rejected"]], ["edge-waf"]
        )
        self.assertTrue(
            all(lead["kind"] != "bypass" for lead in response["state"]["leads"])
        )

    def test_original_cannot_exhaust_while_specialist_work_remains(self) -> None:
        original = self._original_hypothesis()
        self.coordinator(
            self._resisted_event(original, control="waf", authorized=["edge-waf"])
        )
        self.lead_cli("lease", original, "--worker", "hunter")
        error = self.lead_cli(
            "complete",
            original,
            "--worker",
            "hunter",
            "--outcome",
            "exhausted",
            expected=2,
        )
        self.assertIn("specialist", json.dumps(error).casefold())

    def test_completed_bypass_matrix_permits_not_bypassed_terminal(self) -> None:
        original = self._original_hypothesis()
        response = self.coordinator(
            self._resisted_event(original, control="waf", authorized=["edge-waf"])
        )
        bypass_id = response["event"]["result"]["scheduled"][0]["lead_id"]

        self.lead_cli("lease", bypass_id, "--worker", "specialist")
        self.lead_cli(
            "complete",
            bypass_id,
            "--worker",
            "specialist",
            "--outcome",
            "exhausted",
            "--evidence",
            "transformation-class:edge-waf",
            "--evidence",
            "not bypassed under the tested matrix",
        )

        self.lead_cli("lease", original, "--worker", "hunter")
        completed = self.lead_cli(
            "complete",
            original,
            "--worker",
            "hunter",
            "--outcome",
            "exhausted",
        )
        self.assertEqual(completed["status"], "exhausted")
        self.assertIn("not bypassed under the tested matrix", completed["evidence"])


if __name__ == "__main__":
    unittest.main()
