#!/usr/bin/env python3
"""Deterministic tests for evidence-grounded kill-chain re-evaluation.

Graph behaviour is exercised directly against the chain store; scope and
checkpoint invalidation are exercised through the coordinator seam.  All
fixtures are synthetic and never contact a real target.
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

from chain_store import ChainState, ChainStateError, MAX_ASSIGNMENTS  # noqa: E402


class ChainStoreDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.chain = ChainState(Path(self.temporary.name))

    def _node(self, **overrides: object) -> dict[str, object]:
        node = {
            "source_id": "F-node",
            "asset": "app.synthetic.example.test",
            "provides": [],
            "requires": [],
            "severity": "medium",
            "authorized": True,
            "status": "observed",
            "evidence": ["ev:node"],
            "safety_requirements": ["safe:node"],
            "title": "",
        }
        node.update(overrides)
        return node

    def test_demonstrated_prerequisite_creates_one_dedup_assignment(self) -> None:
        self.chain.observe(
            self._node(
                source_id="F-provider",
                provides=["token:admin-session"],
                status="demonstrated",
                evidence=["ev:provider"],
                safety_requirements=["safe:rate"],
            )
        )
        self.chain.observe(
            self._node(
                source_id="F-consumer",
                asset="admin.synthetic.example.test",
                requires=["token:admin-session"],
                evidence=["ev:consumer"],
                safety_requirements=["safe:headers"],
            )
        )
        # Re-observing the same consumer must not multiply the assignment.
        self.chain.observe(
            self._node(
                source_id="F-consumer",
                asset="admin.synthetic.example.test",
                requires=["token:admin-session"],
                evidence=["ev:consumer"],
                safety_requirements=["safe:headers"],
            )
        )
        assignments = self.chain.snapshot()["assignments"]
        self.assertEqual(len(assignments), 1)
        edge = assignments[0]
        self.assertEqual(edge["parents"], ["F-provider", "F-consumer"])
        self.assertEqual(edge["token"], "token:admin-session")
        self.assertEqual(edge["asset"], "admin.synthetic.example.test")
        self.assertEqual(edge["required_evidence"], ["ev:provider", "ev:consumer"])
        self.assertEqual(edge["safety_requirements"], ["safe:rate", "safe:headers"])
        self.assertEqual(edge["status"], "candidate")

    def test_shared_asset_without_prerequisite_creates_no_candidate(self) -> None:
        self.chain.observe(
            self._node(source_id="F-a", provides=["token:foo"], status="demonstrated")
        )
        self.chain.observe(
            self._node(source_id="F-b", requires=["token:bar"])
        )
        self.assertEqual(self.chain.snapshot()["assignments"], [])

    def test_speculative_provider_creates_no_candidate(self) -> None:
        # A provider that only *claims* a capability (not demonstrated) is inert.
        self.chain.observe(
            self._node(source_id="F-a", provides=["token:foo"], status="observed")
        )
        self.chain.observe(self._node(source_id="F-b", requires=["token:foo"]))
        self.assertEqual(self.chain.snapshot()["assignments"], [])

    def test_false_authorization_gate_blocks_edge_execution(self) -> None:
        self.chain.observe(
            self._node(source_id="F-p", provides=["cap:x"], status="demonstrated")
        )
        self.chain.observe(
            self._node(source_id="F-c", requires=["cap:x"], authorized=False)
        )
        edge = self.chain.snapshot()["assignments"][0]
        self.assertEqual(edge["status"], "blocked")
        with self.assertRaises(ChainStateError):
            self.chain.validate(edge["id"], "high", ["ev:demo"])

    def test_validated_chain_is_separate_finding_without_rewriting_components(self) -> None:
        self.chain.observe(
            self._node(
                source_id="F-p",
                provides=["cap:ssrf"],
                status="demonstrated",
                severity="medium",
            )
        )
        self.chain.observe(
            self._node(source_id="F-c", requires=["cap:ssrf"], severity="medium")
        )
        edge = self.chain.snapshot()["assignments"][0]
        finding = self.chain.validate(
            edge["id"], "critical", ["ev:chain-demo"], "Internal takeover via SSRF"
        )
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["parents"], ["F-p", "F-c"])
        self.assertEqual(finding["components"], ["F-p", "F-c"])
        self.assertNotEqual(finding["id"], "F-p")
        # Component findings (nodes) keep their own severity, untouched.
        nodes = {node["source_id"]: node for node in self.chain.snapshot()["nodes"]}
        self.assertEqual(nodes["F-p"]["severity"], "medium")
        self.assertEqual(nodes["F-c"]["severity"], "medium")

    def test_candidate_count_is_bounded(self) -> None:
        self.chain.observe(
            self._node(source_id="F-provider", provides=["cap:x"], status="demonstrated")
        )
        for number in range(MAX_ASSIGNMENTS + 8):
            self.chain.observe(
                self._node(source_id=f"F-consumer-{number}", requires=["cap:x"])
            )
        self.assertEqual(len(self.chain.snapshot()["assignments"]), MAX_ASSIGNMENTS)

    def test_certify_then_material_change_reopens_review(self) -> None:
        self.chain.observe(
            self._node(source_id="F-p", provides=["cap:x"], status="demonstrated")
        )
        self.chain.certify()
        self.assertFalse(self.chain.snapshot()["review_pending"])
        self.chain.observe(self._node(source_id="F-c", requires=["cap:x"]))
        self.assertTrue(self.chain.snapshot()["review_pending"])

    def test_certify_does_not_alter_material_revision(self) -> None:
        self.chain.observe(
            self._node(source_id="F-p", provides=["cap:x"], status="demonstrated")
        )
        before = self.chain.snapshot()["material_revision"]
        self.chain.certify()
        self.assertEqual(self.chain.snapshot()["material_revision"], before)


class ChainCoordinatorTests(unittest.TestCase):
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
                    "intent: Authorized synthetic chain fixture.",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def coordinator(self, event: dict[str, object] | None = None) -> dict[str, object]:
        command = [sys.executable, str(COORDINATOR), "--engagement", str(self.engagement)]
        if event is not None:
            command.extend(("--event", json.dumps(event)))
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return json.loads(result.stdout)

    def _event(self, kind: str, payload: dict[str, object]) -> dict[str, object]:
        return {"schema_version": 1, "type": kind, "payload": payload}

    def test_material_lead_revision_reopens_certified_review(self) -> None:
        certified = self.coordinator(self._event("chain.certify", {}))
        self.assertFalse(certified["chain"]["review_pending"])

        reopened = self.coordinator(
            self._event(
                "lead.upsert",
                {
                    "lead": {
                        "family": "injection",
                        "kind": "validation",
                        "subject": "https://app.synthetic.example.test/x",
                    }
                },
            )
        )
        self.assertTrue(reopened["chain"]["review_pending"])

    def test_out_of_scope_chain_node_is_rejected(self) -> None:
        response = self.coordinator(
            self._event(
                "chain.observe",
                {
                    "node": {
                        "source_id": "F-out",
                        "asset": "evil.example.test",
                        "provides": ["cap:x"],
                        "status": "demonstrated",
                    }
                },
            )
        )
        result = response["event"]["result"]
        self.assertFalse(result["accepted"])
        self.assertTrue(result["operator_gate"])
        self.assertEqual(response["chain"]["nodes"], [])


if __name__ == "__main__":
    unittest.main()
