#!/usr/bin/env python3
"""Black-box contract tests for the lead-state CLI and published schemas."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "lead_state.py"


class LeadStateCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engagement = Path(self.temp.name)

    def run_cli(self, *args, expected=0):
        result = subprocess.run(
            [sys.executable, str(CLI), "--engagement", str(self.engagement), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def test_cli_runs_lead_lifecycle_and_reports_convergence(self):
        lead = self.run_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "access-control",
                    "kind": "endpoint",
                    "subject": "https://cli.example.test/api/items/9",
                    "priority": 70,
                    "provenance": ["recon:synthetic"],
                    "evidence": [],
                }
            ),
        )["lead"]
        self.run_cli(
            "coverage",
            "--dimension",
            "family",
            "--key",
            "access-control",
            "--status",
            "tested",
        )
        leased = self.run_cli("lease", "--worker", "worker-cli")
        self.assertEqual(leased["id"], lead["id"])
        self.run_cli(
            "complete",
            lead["id"],
            "--worker",
            "worker-cli",
            "--outcome",
            "completed",
            "--evidence",
            "observation:synthetic-check-complete",
        )
        status = self.run_cli("status")
        self.assertTrue(status["allowed"])
        self.assertEqual(status["reasons"], ["converged"])

    def test_lease_can_target_a_known_lead_without_claiming_higher_priority_work(self):
        high_priority = self.run_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "client-side",
                    "kind": "endpoint",
                    "subject": "https://cli.example.test/high-priority",
                    "priority": 90,
                    "provenance": ["recon:parallel-worker"],
                    "evidence": [],
                }
            ),
        )["lead"]
        intended = self.run_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "auth-session",
                    "kind": "endpoint",
                    "subject": "https://cli.example.test/intended",
                    "priority": 60,
                    "provenance": ["recon:current-worker"],
                    "evidence": [],
                }
            ),
        )["lead"]

        leased = self.run_cli(
            "lease", intended["id"], "--worker", "worker-cli"
        )

        self.assertEqual(leased["id"], intended["id"])
        snapshot = self.run_cli("snapshot")
        leads = {lead["id"]: lead for lead in snapshot["leads"]}
        self.assertEqual(leads[intended["id"]]["status"], "leased")
        self.assertEqual(leads[high_priority["id"]]["status"], "queued")

    def test_release_immediately_returns_an_accidental_lease_to_the_queue(self):
        self.run_cli("configure", "--max-attempts", "1")
        lead = self.run_cli(
            "upsert",
            "--json",
            json.dumps(
                {
                    "family": "client-side",
                    "kind": "endpoint",
                    "subject": "https://cli.example.test/accidental",
                    "priority": 90,
                    "provenance": ["recon:parallel-worker"],
                    "evidence": [],
                }
            ),
        )["lead"]
        self.run_cli("lease", "--worker", "wrong-worker")

        released = self.run_cli(
            "release", lead["id"], "--worker", "wrong-worker"
        )

        self.assertEqual(released["id"], lead["id"])
        self.assertEqual(released["status"], "queued")
        self.assertEqual(released["attempts"], 0)
        self.assertNotIn("lease_owner", released)
        self.assertNotIn("lease_until", released)
        reclaimed = self.run_cli(
            "lease", lead["id"], "--worker", "right-worker"
        )
        self.assertEqual(reclaimed["id"], lead["id"])

    def test_status_uses_nonzero_exit_when_work_remains(self):
        status = self.run_cli("status", expected=3)
        self.assertFalse(status["allowed"])
        self.assertEqual(status["reasons"], ["coverage_empty"])

    def test_cli_configures_and_consumes_request_and_progress_budgets(self):
        configured = self.run_cli(
            "configure", "--max-requests", "2", "--max-seconds", "60"
        )
        self.assertEqual(configured["max_requests"], 2)
        consumed = self.run_cli("request", "--count", "2")
        self.assertEqual(consumed["loop"]["requests"], 2)
        self.assertIn("request_budget_exhausted", consumed["can_stop"]["reasons"])
        iteration = self.run_cli(
            "iteration", "--progress-count", "2", "--surface-delta", "1"
        )
        self.assertEqual(iteration["loop"]["progress_count"], 2)
        self.assertEqual(iteration["loop"]["surface_delta"], 1)

    def test_cli_accepts_only_versioned_scenario_coverage(self):
        accepted = self.run_cli(
            "coverage",
            "--dimension",
            "scenario",
            "--key",
            "WSTG-v42-ATHN-01",
            "--status",
            "tested",
        )
        self.assertEqual(accepted["coverage"]["dimension"], "scenario")
        result = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--engagement",
                str(self.engagement),
                "coverage",
                "--dimension",
                "scenario",
                "--key",
                "WSTG-ATHN-01",
                "--status",
                "tested",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("versioned", result.stderr)

    def test_published_state_schemas_are_valid_json_schema_documents(self):
        for name in ("lead-v1.schema.json", "coverage-v1.schema.json", "lead-state-v1.schema.json"):
            document = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(document["type"], "object")
            self.assertFalse(document["additionalProperties"])
        lead = json.loads((ROOT / "schemas" / "lead-v1.schema.json").read_text())
        for field in ("hypothesis", "parent_leads", "parent_findings", "safety_requirements"):
            self.assertIn(field, lead["required"])
            self.assertIn(field, lead["properties"])
        coverage = json.loads((ROOT / "schemas" / "coverage-v1.schema.json").read_text())
        self.assertIn("scenario", coverage["properties"]["dimension"]["enum"])
        self.assertIn("allOf", coverage)
        state = json.loads((ROOT / "schemas" / "lead-state-v1.schema.json").read_text())
        loop = state["properties"]["loop"]
        for field in (
            "requests",
            "max_requests",
            "max_seconds",
            "started_at",
            "progress_count",
            "surface_delta",
        ):
            self.assertIn(field, loop["required"])
            self.assertIn(field, loop["properties"])

    def test_concurrent_upserts_leave_one_valid_row_per_fingerprint(self):
        processes = []
        for number in range(12):
            payload = json.dumps(
                {
                    "family": "surface-inventory",
                    "kind": "endpoint",
                    "subject": f"https://parallel.example.test/routes/{number % 6}",
                    "priority": number,
                    "provenance": [f"recon:synthetic-{number}"],
                    "evidence": [],
                }
            )
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(CLI),
                        "--engagement",
                        str(self.engagement),
                        "upsert",
                        "--json",
                        payload,
                    ],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
        for process in processes:
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr or stdout)

        snapshot = self.run_cli("snapshot")
        self.assertEqual(len(snapshot["leads"]), 6)
        self.assertEqual(len({lead["fingerprint"] for lead in snapshot["leads"]}), 6)


if __name__ == "__main__":
    unittest.main()
