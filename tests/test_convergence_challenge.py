#!/usr/bin/env python3
"""Deterministic tests for the isolated-explorer convergence challenge.

Challenge bookkeeping is exercised directly against the challenge store; lens
scheduling, the explorer quality gate, and digest binding are exercised through
the coordinator seam.  Every fixture is synthetic and never contacts a target.
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
sys.path.insert(0, str(ROOT / "lib"))

from challenge_store import LENSES, ChallengeState, ChallengeStateError  # noqa: E402
from finding_store import upsert  # noqa: E402
from lead_store import LeadState  # noqa: E402


class ChallengeStoreDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.challenge = ChallengeState(Path(self.temporary.name))

    def test_open_schedules_all_three_lenses_for_the_digest(self) -> None:
        opened = self.challenge.open("digest-a")
        self.assertEqual(opened["status"], "open")
        self.assertEqual(opened["digest"], "digest-a")
        self.assertEqual(set(opened["lenses"]), set(LENSES))
        self.assertTrue(all(state == "pending" for state in opened["lenses"].values()))
        self.assertEqual(len(LENSES), 3)

    def test_zero_lead_round_certifies_only_for_its_digest(self) -> None:
        self.challenge.open("digest-a")
        for lens in LENSES:
            self.challenge.record(lens, "digest-a", [], [{"subject": "x", "reason": "unsupported"}])
        self.assertEqual(self.challenge.snapshot()["status"], "certified")
        self.assertTrue(self.challenge.reporting_permitted("digest-a"))
        # A drifted campaign digest no longer matches the certified round.
        self.assertFalse(self.challenge.reporting_permitted("digest-b"))

    def test_one_accepted_lead_invalidates_and_reopens(self) -> None:
        self.challenge.open("digest-a")
        self.challenge.record("surface-archaeologist", "digest-a", ["L-abc"], [])
        self.assertEqual(self.challenge.snapshot()["status"], "reopened")
        self.assertFalse(self.challenge.reporting_permitted("digest-a"))
        # Remaining lenses cannot rescue an already-invalidated round.
        self.challenge.record("abuse-case-adversary", "digest-a", [], [])
        self.challenge.record("boundary-breaker", "digest-a", [], [])
        self.assertEqual(self.challenge.snapshot()["status"], "reopened")

    def test_next_round_runs_against_the_updated_digest(self) -> None:
        self.challenge.open("digest-a")
        for lens in LENSES:
            self.challenge.record(lens, "digest-a", [], [])
        self.assertEqual(self.challenge.snapshot()["status"], "certified")
        # Reopened terminal work changed the digest; a fresh round starts clean.
        reopened = self.challenge.open("digest-b")
        self.assertEqual(reopened["status"], "open")
        self.assertTrue(all(state == "pending" for state in reopened["lenses"].values()))
        self.assertFalse(self.challenge.reporting_permitted("digest-a"))

    def test_open_is_idempotent_for_the_same_digest(self) -> None:
        self.challenge.open("digest-a")
        self.challenge.record("surface-archaeologist", "digest-a", [], [])
        again = self.challenge.open("digest-a")
        # Re-opening the live round must not wipe an in-flight submission.
        self.assertEqual(again["lenses"]["surface-archaeologist"], "submitted")

    def test_record_requires_the_bound_digest_and_a_known_lens(self) -> None:
        self.challenge.open("digest-a")
        with self.assertRaises(ChallengeStateError):
            self.challenge.record("surface-archaeologist", "digest-stale", [], [])
        with self.assertRaises(ChallengeStateError):
            self.challenge.record("unknown-lens", "digest-a", [], [])


class ChallengeCoordinatorTests(unittest.TestCase):
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
                    "intent: Authorized synthetic convergence fixture.",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.store = LeadState(self.engagement)

    def coordinator(self, event: dict[str, object] | None = None) -> dict[str, object]:
        command = [sys.executable, str(COORDINATOR), "--engagement", str(self.engagement)]
        if event is not None:
            command.extend(("--event", json.dumps(event)))
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def _event(self, kind: str, payload: dict[str, object]) -> dict[str, object]:
        return {"schema_version": 1, "type": kind, "payload": payload}

    def _open(self) -> dict[str, object]:
        seeded = self.coordinator()
        for entry in seeded["state"]["coverage"]:
            self.store.record_coverage(
                "workflow", entry["key"], "tested", reason="synthetic completion"
            )
        self.coordinator(self._event("chain.certify", {}))
        return self.coordinator(self._event("challenge.open", {}))

    def _explorer(self, **overrides: object) -> dict[str, object]:
        lead = {
            "family": "access-control",
            "kind": "exploration",
            "subject": "https://app.synthetic.example.test/admin",
            "hypothesis": "An unreferenced admin route may skip the role check.",
            "observation": "A client bundle string referenced /admin without a link.",
            "next_test": "Request /admin anonymously and compare to an authorized role.",
            "provenance": ["explorer:boundary-breaker"],
            "priority": 70,
            "safety_requirements": ["honor rate policy", "no destructive verbs"],
        }
        lead.update(overrides)
        return lead

    def _submit(self, lens: str, leads: list[dict[str, object]]) -> dict[str, object]:
        return self.coordinator(self._event("challenge.submit", {"lens": lens, "leads": leads}))

    def test_open_schedules_three_isolated_lenses_with_a_shared_digest(self) -> None:
        response = self._open()
        result = response["event"]["result"]
        self.assertEqual(result["lenses"], list(LENSES))
        self.assertEqual(result["digest"], response["material_digest"])
        self.assertIn("leads", result["material"])
        self.assertIn("coverage", result["material"])
        self.assertIn("surface", result["material"])
        self.assertIn("findings", result["material"])
        self.assertIn("chain", result["material"])
        self.assertEqual(response["challenge"]["status"], "open")
        resumed = self.coordinator()
        self.assertEqual(resumed["next_action"]["kind"], "challenge-lens")
        self.assertEqual(resumed["next_action"]["material"], result["material"])

    def test_open_rejects_incomplete_or_unreviewed_campaigns(self) -> None:
        event = self._event("challenge.open", {})
        command = [
            sys.executable,
            str(COORDINATOR),
            "--engagement",
            str(self.engagement),
            "--event",
            json.dumps(event),
        ]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires converged", result.stderr)

    def test_supported_unique_lead_reopens_normal_work(self) -> None:
        opened = self._open()
        support = opened["event"]["result"]["material"]["coverage"][0]["key"]
        response = self._submit(
            "boundary-breaker",
            [self._explorer(provenance=[support, "explorer:boundary-breaker"])],
        )
        result = response["event"]["result"]
        self.assertEqual(len(result["accepted"]), 1)
        self.assertTrue(result["reopened"])
        self.assertEqual(response["challenge"]["status"], "reopened")
        accepted_id = result["accepted"][0]["lead_id"]
        ids = {lead["id"] for lead in response["state"]["leads"]}
        self.assertIn(accepted_id, ids)
        self.assertFalse(response["reporting_permitted"])

    def test_finding_id_is_valid_support_for_an_explorer_lead(self) -> None:
        upsert(
            self.engagement,
            {
                "id": "F-synthetic-support",
                "technique": "synthetic observation",
                "family": "access-control",
                "severity": "low",
                "status": "suspected",
                "summary": "Synthetic workflow clue",
                "endpoint": "https://app.synthetic.example.test/workflow",
            },
        )
        self._open()
        response = self._submit(
            "abuse-case-adversary",
            [self._explorer(provenance=["F-synthetic-support"])],
        )
        self.assertEqual(len(response["event"]["result"]["accepted"]), 1)

    def test_low_quality_ideas_are_rejected_without_counting_as_progress(self) -> None:
        opened = self._open()
        support = opened["event"]["result"]["material"]["coverage"][0]["key"]
        before = {lead["id"] for lead in opened["state"]["leads"]}
        base = self._explorer(provenance=[support, "explorer:boundary-breaker"])

        incomplete = {key: value for key, value in base.items() if key != "next_test"}
        out_of_scope = self._explorer(
            subject="https://evil.example.test/admin",
            provenance=[support, "explorer:boundary-breaker"],
        )
        unsupported = self._explorer(provenance=["explorer:only-self-reference"])
        prohibited = self._explorer(
            subject="https://app.synthetic.example.test/report",
            hypothesis="Trigger a denial-of-service by exhausting the worker pool.",
            provenance=[support, "explorer:boundary-breaker"],
        )
        response = self._submit(
            "abuse-case-adversary", [incomplete, out_of_scope, unsupported, prohibited]
        )
        reasons = {item["reason"] for item in response["event"]["result"]["rejected"]}
        self.assertEqual(
            reasons, {"incomplete", "out-of-scope", "unsupported", "prohibited"}
        )
        self.assertEqual(response["event"]["result"]["accepted"], [])
        after = {lead["id"] for lead in response["state"]["leads"]}
        self.assertEqual(before, after)

    def test_duplicate_and_already_tested_ideas_are_distinguished(self) -> None:
        # Seed one terminal lead so an identical idea reads as already-tested.
        tested = self.store.ensure_lead(
            {
                "family": "injection",
                "kind": "validation",
                "subject": "https://app.synthetic.example.test/search",
                "method": "GET",
                "parameter": "q",
            }
        )["lead"]
        self.store.lease_lead(tested["id"], "worker-1")
        self.store.complete_lead(tested["id"], "worker-1", "completed")

        opened = self._open()
        support = opened["event"]["result"]["material"]["coverage"][0]["key"]
        fresh = self._explorer(provenance=[support, "explorer:boundary-breaker"])
        already_tested = self._explorer(
            family="injection",
            kind="validation",
            subject="https://app.synthetic.example.test/search",
            method="GET",
            parameter="q",
            provenance=[support, "explorer:boundary-breaker"],
        )
        response = self._submit("surface-archaeologist", [fresh, dict(fresh), already_tested])
        result = response["event"]["result"]
        self.assertEqual(len(result["accepted"]), 1)
        reasons = [item["reason"] for item in result["rejected"]]
        self.assertIn("duplicate", reasons)
        self.assertIn("already-tested", reasons)

    def test_zero_lead_challenge_certifies_for_the_current_digest(self) -> None:
        self._open()
        response: dict[str, object] = {}
        for lens in LENSES:
            response = self._submit(lens, [])
        self.assertEqual(response["challenge"]["status"], "certified")
        self.assertEqual(response["challenge"]["digest"], response["material_digest"])

    def test_challenge_bookkeeping_does_not_alter_the_material_digest(self) -> None:
        opened = self._open()
        digest = opened["material_digest"]
        support = opened["event"]["result"]["material"]["coverage"][0]["key"]
        rejected_only = self._submit(
            "boundary-breaker",
            [self._explorer(subject="https://evil.example.test/x", provenance=[support])],
        )
        self.assertEqual(rejected_only["material_digest"], digest)
        self.assertEqual(rejected_only["event"]["result"]["accepted"], [])

    def test_submission_rejects_material_drift(self) -> None:
        self._open()
        self.store.ensure_lead(
            {
                "family": "access-control",
                "kind": "validation",
                "subject": "https://app.synthetic.example.test/drift",
            }
        )
        event = self._event(
            "challenge.submit",
            {"lens": "surface-archaeologist", "leads": []},
        )
        result = subprocess.run(
            [
                sys.executable,
                str(COORDINATOR),
                "--engagement",
                str(self.engagement),
                "--event",
                json.dumps(event),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("material changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
