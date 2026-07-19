#!/usr/bin/env python3
"""Black-box tests for recursive campaign surface-delta ingestion."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "campaign_coordinator.py"
LEADS = ROOT / "scripts" / "lead_state.py"


class SurfaceDeltaTests(unittest.TestCase):
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
                    '  - "*.synthetic.example.test"',
                    "out_of_scope:",
                    "  - denied.synthetic.example.test",
                    "intent: Authorized synthetic surface fixture.",
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

    def observe(
        self,
        source: str,
        kind: str,
        value: str,
        *,
        parent: str = "",
        attributes: dict[str, object] | None = None,
    ) -> dict[str, object]:
        observation: dict[str, object] = {
            "kind": kind,
            "value": value,
            "attributes": attributes or {},
        }
        if parent:
            observation["parent"] = parent
        event = {
            "schema_version": 1,
            "type": "surface.observed",
            "payload": {"source": source, "observation": observation},
        }
        return self.run_json(
            [
                sys.executable,
                str(CLI),
                "--engagement",
                str(self.engagement),
                "--event",
                json.dumps(event),
            ]
        )

    def coverage(self, key: str, status: str) -> None:
        self.run_json(
            [
                sys.executable,
                str(LEADS),
                "--engagement",
                str(self.engagement),
                "coverage",
                "--dimension",
                "workflow",
                "--key",
                key,
                "--status",
                status,
            ]
        )

    def test_all_agent_sources_use_one_idempotent_ingestion_path(self) -> None:
        for source in ("recon", "hunter", "bypass", "exploit", "explorer"):
            host = f"{source}.synthetic.example.test"
            response = self.observe(source, "host", host)
            self.assertEqual(response["event"]["result"]["result"], "appended")
            self.assertEqual(response["event"]["result"]["progress"], 1)
            self.assertTrue(
                any(lead["subject"] == host for lead in response["state"]["leads"])
            )

        before = response["state"]["loop"]["progress_count"]
        duplicate = self.observe("hunter", "host", "recon.synthetic.example.test")
        self.assertEqual(duplicate["event"]["result"]["result"], "duplicate")
        self.assertEqual(duplicate["event"]["result"]["progress"], 0)
        self.assertEqual(duplicate["state"]["loop"]["progress_count"], before)
        observations = duplicate["surface"]["observations"]
        self.assertEqual(len(observations), 5)

    def test_supported_surface_kinds_create_recursive_work(self) -> None:
        examples = (
            ("host", "nested.synthetic.example.test", ""),
            ("endpoint", "https://app.synthetic.example.test/api/items", ""),
            ("schema", "https://app.synthetic.example.test/openapi.json", ""),
            ("parameter", "item_id", "https://app.synthetic.example.test/api/items"),
            ("role", "billing-admin", "https://app.synthetic.example.test/account"),
        )
        for kind, value, parent in examples:
            with self.subTest(kind=kind):
                response = self.observe("recon", kind, value, parent=parent)
                applied = response["event"]["result"]
                self.assertTrue(applied["accepted"])
                self.assertGreater(len(applied["coverage_ids"]), 0)
                self.assertGreater(len(applied["work_ids"]), 0)

    def test_material_change_reopens_only_applicable_coverage(self) -> None:
        endpoint = "https://app.synthetic.example.test/api/v1/items"
        self.observe("recon", "endpoint", endpoint, attributes={"version": "1"})
        dns_key = "asset=app.synthetic.example.test;method=dns;role=anonymous"
        content_key = (
            "asset=app.synthetic.example.test;method=content-discovery;role=anonymous"
        )
        self.coverage(dns_key, "tested")
        self.coverage(content_key, "tested")

        changed = self.observe(
            "hunter", "endpoint", endpoint, attributes={"version": "2"}
        )

        self.assertEqual(changed["event"]["result"]["result"], "changed")
        rows = {entry["key"]: entry for entry in changed["state"]["coverage"]}
        self.assertEqual(rows[dns_key]["status"], "tested")
        self.assertEqual(rows[content_key]["status"], "not-tested")

    def test_out_of_scope_and_ambiguous_observations_do_not_create_work(self) -> None:
        denied = self.observe("recon", "host", "denied.synthetic.example.test")
        self.assertFalse(denied["event"]["result"]["accepted"])
        self.assertTrue(denied["event"]["result"]["operator_gate"])

        ambiguous = self.observe("explorer", "parameter", "account_id")
        self.assertFalse(ambiguous["event"]["result"]["accepted"])
        self.assertTrue(ambiguous["event"]["result"]["operator_gate"])
        self.assertEqual(ambiguous["surface"]["observations"], [])


if __name__ == "__main__":
    unittest.main()
