#!/usr/bin/env python3
"""Contract tests for the durable lead and coverage state module."""

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from lead_store import LeadState, LeadStateError  # noqa: E402


class LeadStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = LeadState(Path(self.temp.name))

    def test_upsert_deduplicates_by_stable_identity_and_merges_provenance(self):
        first = self.store.upsert_lead(
        {
            "family": "access-control",
            "kind": "endpoint",
            "subject": "https://app.example.test/api/widgets/7",
            "method": "GET",
            "parameter": "widget_id",
            "priority": 30,
            "provenance": ["recon:route-inventory"],
            "evidence": ["observation:route-present"],
        }
    )
        second = self.store.upsert_lead(
        {
            "family": "ACCESS-CONTROL",
            "kind": "endpoint",
            "subject": "https://app.example.test/api/widgets/7",
            "method": "get",
            "parameter": "widget_id",
            "priority": 80,
            "provenance": ["finding:synthetic-001"],
            "evidence": ["observation:identifier-sequential"],
        }
    )

        self.assertEqual(first["result"], "appended")
        self.assertEqual(second["result"], "updated")
        self.assertEqual(second["lead"]["id"], first["lead"]["id"])
        self.assertEqual(second["lead"]["priority"], 80)
        self.assertEqual(
            second["lead"]["provenance"],
            ["recon:route-inventory", "finding:synthetic-001"],
        )
        self.assertEqual(
            second["lead"]["evidence"],
            ["observation:route-present", "observation:identifier-sequential"],
        )
        self.assertEqual(len(self.store.snapshot()["leads"]), 1)

    def test_upsert_merges_lead_lineage_safety_and_hypothesis_without_secret_fields(self):
        first = self.store.upsert_lead(
            {
                "family": "access-control",
                "kind": "endpoint",
                "subject": "https://lineage.example.test/api/widgets/7",
                "hypothesis": "A peer identifier may cross an authorization boundary.",
                "parent_leads": ["L-0123456789abcdef"],
                "parent_findings": ["F-SYNTHETIC-001"],
                "safety_requirements": ["read-only"],
                "provenance": ["recon:synthetic"],
                "evidence": [],
            }
        )
        second = self.store.upsert_lead(
            {
                "family": "access-control",
                "kind": "endpoint",
                "subject": "https://lineage.example.test/api/widgets/7",
                "hypothesis": "A stronger synthetic hypothesis replaces the earlier wording.",
                "parent_leads": ["L-fedcba9876543210"],
                "parent_findings": ["F-SYNTHETIC-002"],
                "safety_requirements": ["no-credential-use"],
                "provenance": ["finding:synthetic"],
                "evidence": [],
            }
        )

        lead = second["lead"]
        self.assertEqual(lead["id"], first["lead"]["id"])
        self.assertEqual(
            lead["parent_leads"], ["L-0123456789abcdef", "L-fedcba9876543210"]
        )
        self.assertEqual(
            lead["parent_findings"], ["F-SYNTHETIC-001", "F-SYNTHETIC-002"]
        )
        self.assertEqual(lead["safety_requirements"], ["read-only", "no-credential-use"])
        self.assertEqual(
            lead["hypothesis"],
            "A stronger synthetic hypothesis replaces the earlier wording.",
        )
        self.assertNotIn("secret", lead)
        with self.assertRaisesRegex(LeadStateError, "unsupported lead fields"):
            self.store.upsert_lead(
                {
                    "family": "access-control",
                    "kind": "endpoint",
                    "subject": "https://rejected.example.test/",
                    "raw_secret": "synthetic-placeholder",
                }
            )

    def test_lease_is_priority_ordered_and_stale_lease_is_recovered(self):
        current = ["2026-01-01T00:00:00Z"]
        self.store = LeadState(Path(self.temp.name), clock=lambda: current[0])
        low = self._add_lead("https://low.example.test/", priority=10)
        high = self._add_lead("https://high.example.test/", priority=90)

        leased = self.store.lease_next("worker-synthetic", lease_seconds=30)
        self.assertEqual(leased["id"], high["id"])
        self.assertEqual(leased["attempts"], 1)
        with self.assertRaisesRegex(LeadStateError, "lease owner"):
            self.store.complete_lead(high["id"], "different-worker", "completed")

        current[0] = "2026-01-01T00:00:31Z"
        recovered = self.store.lease_next("worker-recovery", lease_seconds=30)
        self.assertEqual(recovered["id"], high["id"])
        self.assertEqual(recovered["attempts"], 2)
        done = self.store.complete_lead(
            high["id"],
            "worker-recovery",
            "completed",
            evidence=["observation:authorization-enforced"],
        )
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["evidence"], ["observation:authorization-enforced"])
        self.assertEqual(self.store.lease_next("worker-next")["id"], low["id"])

    def test_stale_lead_at_attempt_limit_becomes_exhausted(self):
        current = ["2026-01-01T00:00:00Z"]
        self.store = LeadState(Path(self.temp.name), clock=lambda: current[0])
        self.store.configure_loop(max_attempts=1)
        lead = self._add_lead("https://attempt.example.test/")
        self.store.lease_next("worker-synthetic", lease_seconds=5)

        current[0] = "2026-01-01T00:00:06Z"
        self.assertIsNone(self.store.lease_next("worker-recovery"))
        stored = self.store.snapshot()["leads"][0]
        self.assertEqual(stored["id"], lead["id"])
        self.assertEqual(stored["status"], "exhausted")

    def test_convergence_check_recovers_abandoned_stale_lease(self):
        current = ["2026-01-01T00:00:00Z"]
        self.store = LeadState(Path(self.temp.name), clock=lambda: current[0])
        self.store.configure_loop(max_attempts=1)
        self.store.record_coverage("family", "access-control", "tested")
        self._add_lead("https://abandoned.example.test/")
        self.store.lease_next("worker-abandoned", lease_seconds=5)

        current[0] = "2026-01-01T00:00:06Z"
        stopped = self.store.can_stop()
        self.assertTrue(stopped["allowed"])
        self.assertEqual(stopped["reasons"], ["converged"])
        self.assertEqual(self.store.snapshot()["leads"][0]["status"], "exhausted")

    def test_coverage_ledger_validates_status_and_upserts_stable_key(self):
        first = self.store.record_coverage(
            "endpoint",
            "GET https://app.example.test/api/widgets",
            "not-tested",
            reason="authorization matrix pending",
        )
        second = self.store.record_coverage(
            "endpoint",
            "GET https://app.example.test/api/widgets",
            "tested",
            reason="synthetic authorization matrix completed",
        )

        self.assertEqual(first["result"], "appended")
        self.assertEqual(second["result"], "updated")
        self.assertEqual(first["coverage"]["id"], second["coverage"]["id"])
        self.assertEqual(second["coverage"]["status"], "tested")
        with self.assertRaisesRegex(LeadStateError, "coverage status"):
            self.store.record_coverage("family", "access-control", "done")
        for status in ("blocked", "not-tested"):
            with self.assertRaisesRegex(LeadStateError, "reason"):
                self.store.record_coverage("family", f"synthetic-{status}", status)

    def test_versioned_scenario_coverage_rejects_mutable_identifiers(self):
        wstg = self.store.record_coverage(
            "scenario", "WSTG-v42-ATHN-01", "tested"
        )
        asvs = self.store.record_coverage(
            "scenario", "v5.0.0-1.2.3", "not-tested", reason="scenario queued"
        )
        self.assertEqual(wstg["coverage"]["key"], "WSTG-v42-ATHN-01")
        self.assertEqual(asvs["coverage"]["key"], "v5.0.0-1.2.3")
        for key in ("WSTG-ATHN-01", "latest-1.2.3", "v5-1.2.3"):
            with self.assertRaisesRegex(LeadStateError, "versioned"):
                self.store.record_coverage("scenario", key, "tested")

    def test_convergence_requires_terminal_coverage_and_no_actionable_leads(self):
        self.assertEqual(self.store.can_stop()["reasons"], ["coverage_empty"])
        self.store.record_coverage(
            "family", "access-control", "not-tested", reason="family queued"
        )
        lead = self._add_lead("https://queue.example.test/")
        pending = self.store.can_stop()
        self.assertFalse(pending["allowed"])
        self.assertEqual(pending["actionable"], 1)
        self.assertIn("coverage_not_tested", pending["reasons"])

        self.store.record_coverage("family", "access-control", "exhausted")
        leased = self.store.lease_next("worker-synthetic")
        self.store.complete_lead(leased["id"], "worker-synthetic", "completed")
        converged = self.store.can_stop()
        self.assertTrue(converged["allowed"])
        self.assertEqual(converged["reasons"], ["converged"])
        self.assertEqual(lead["id"], leased["id"])

    def test_loop_budgets_bound_repeated_no_progress(self):
        self.store.record_coverage(
            "family", "access-control", "not-tested", reason="family queued"
        )
        self._add_lead("https://bounded.example.test/")
        self.store.configure_loop(max_iterations=10, max_no_progress_rounds=2)
        first = self.store.record_iteration(progress=False)
        self.assertFalse(first["can_stop"]["allowed"])
        second = self.store.record_iteration(progress=False)
        self.assertTrue(second["can_stop"]["allowed"])
        self.assertEqual(second["can_stop"]["reasons"], ["no_progress_budget_exhausted"])

    def test_request_and_elapsed_time_budgets_are_independent(self):
        current = ["2026-01-01T00:00:00Z"]
        request_store = LeadState(Path(self.temp.name), clock=lambda: current[0])
        request_store.configure_loop(max_requests=2, max_seconds=100)
        request_store.record_coverage(
            "family", "access-control", "not-tested", reason="family queued"
        )
        request_store.record_requests(1)
        self.assertFalse(request_store.can_stop()["allowed"])
        exhausted = request_store.record_requests(1)["can_stop"]
        self.assertTrue(exhausted["allowed"])
        self.assertIn("request_budget_exhausted", exhausted["reasons"])

        with tempfile.TemporaryDirectory() as other:
            current = ["2026-01-01T00:00:00Z"]
            time_store = LeadState(Path(other), clock=lambda: current[0])
            time_store.configure_loop(max_requests=100, max_seconds=10)
            time_store.record_coverage(
                "family", "access-control", "not-tested", reason="family queued"
            )
            current[0] = "2026-01-01T00:00:11Z"
            timed_out = time_store.can_stop()
            self.assertTrue(timed_out["allowed"])
            self.assertIn("time_budget_exhausted", timed_out["reasons"])

    def test_iteration_records_progress_count_and_surface_delta(self):
        first = self.store.record_iteration(progress_count=2, surface_delta=3)
        self.assertEqual(first["loop"]["progress_count"], 2)
        self.assertEqual(first["loop"]["surface_delta"], 3)
        self.assertEqual(first["loop"]["no_progress_rounds"], 0)
        second = self.store.record_iteration(progress_count=0, surface_delta=0)
        self.assertEqual(second["loop"]["progress_count"], 2)
        self.assertEqual(second["loop"]["surface_delta"], 0)
        self.assertEqual(second["loop"]["no_progress_rounds"], 1)

    def test_state_file_is_private_and_invalid_input_does_not_replace_it(self):
        self._add_lead("https://private.example.test/")
        path = Path(self.temp.name) / "state" / "lead-state.json"
        before = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(LeadStateError):
            self.store.upsert_lead(
                {
                    "family": "access-control",
                    "kind": "endpoint",
                    "subject": "https://invalid.example.test/",
                    "priority": 101,
                }
            )
        self.assertEqual(path.read_bytes(), before)

    def test_snapshot_rejects_state_that_does_not_match_published_shape(self):
        state_dir = Path(self.temp.name) / "state"
        state_dir.mkdir()
        (state_dir / "lead-state.json").write_text(
            '{"schema_version":1,"revision":0,"leads":"invalid","coverage":[],"loop":{}}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LeadStateError, "state schema"):
            self.store.snapshot()

    def _add_lead(self, subject, priority=50):
        return self.store.upsert_lead(
            {
                "family": "access-control",
                "kind": "endpoint",
                "subject": subject,
                "priority": priority,
                "provenance": ["recon:synthetic"],
                "evidence": [],
            }
        )["lead"]


if __name__ == "__main__":
    unittest.main()
