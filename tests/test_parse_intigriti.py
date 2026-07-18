#!/usr/bin/env python3
"""Offline contract tests for the Intigriti engagement parser."""

from __future__ import annotations

import importlib.util
import json
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from lib.harness_config import load_engagement, scope_decision


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "parse_intigriti.py"
FIXTURE = ROOT / "tests" / "fixtures" / "intigriti_heretechnologies.json"
TEST_USERNAME = "synthetic-researcher"


def load_module():
    spec = importlib.util.spec_from_file_location("parse_intigriti", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IntigritiParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.program = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_parser_entry_point_exists(self) -> None:
        self.assertTrue(SCRIPT.is_file())

    def test_parser_api_is_available(self) -> None:
        for name in ("parse_program_ref", "parse_tiers", "parse_scope", "parse_roe", "build_yaml"):
            self.assertTrue(hasattr(self.module, name), name)

    def generated(self) -> dict:
        return self.module.build_yaml(self.program, TEST_USERNAME, assume_yes=True)

    def test_fixture_is_minimized_and_contains_no_secret_material(self) -> None:
        self.assertNotIn("lastContributors", self.program)
        self.assertNotIn("lastActivity", self.program)
        self.assertNotIn("programId", self.program)
        forbidden_keys = {
            "authorization", "cookie", "password", "passwd", "secret",
            "token", "accesstoken", "refreshtoken", "apikey", "privatekey",
        }

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield str(key).replace("_", "").replace("-", "").casefold()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        self.assertEqual(forbidden_keys.intersection(keys(self.program)), set())
        raw = FIXTURE.read_text(encoding="utf-8")
        secret_patterns = (
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        )
        for pattern in secret_patterns:
            self.assertIsNone(re.search(pattern, raw, re.IGNORECASE), pattern)

    def test_program_reference_accepts_slug_and_detail_url_only(self) -> None:
        expected = ("heretechnologies", "heretechnologies")
        self.assertEqual(self.module.parse_program_ref("heretechnologies/heretechnologies"), expected)
        self.assertEqual(
            self.module.parse_program_ref(
                "https://app.intigriti.com/researcher/programs/"
                "heretechnologies/heretechnologies/detail"
            ),
            expected,
        )
        with self.assertRaisesRegex(ValueError, "company/program"):
            self.module.parse_program_ref("here.com")

    def test_golden_scope_contains_only_paying_web_assets(self) -> None:
        generated = self.generated()
        self.assertEqual(
            generated["targets"],
            [
                "*.account.api.here.com",
                "*.account.here.com",
                "*.mobilitygraph.hereapi.com",
                "*.router.hereapi.com",
                "*.scbe.api.here.com",
                "*.subp-router.hereapi.com",
                "jaguar.here.com",
                "landrover.here.com",
                "*.here.com",
                "*.hereapi.com",
            ],
        )
        self.assertNotIn("955837609", generated["targets"])
        self.assertNotIn("com.here.app.maps", generated["targets"])
        self.assertNotIn("Leaked/compromised employee accounts *.here.com", generated["targets"])
        self.assertIn("955837609", generated["notes"])
        self.assertIn("com.here.app.maps", generated["notes"])
        self.assertIn("Leaked/compromised employee accounts", generated["notes"])

    def test_tier_floors_are_derived_from_paid_ranges(self) -> None:
        generated = self.generated()
        containing = {
            pattern: tier["report_floor"]
            for tier in generated["tiers"].values()
            for pattern in tier["patterns"]
        }
        self.assertEqual(containing["*.here.com"], "exceptional")
        self.assertEqual(containing["*.hereapi.com"], "exceptional")
        self.assertEqual(containing["*.account.here.com"], "low")
        self.assertNotIn("account.here.com", containing)

    def test_rate_header_and_roe_defaults_are_fail_closed(self) -> None:
        generated = self.generated()
        self.assertEqual(generated["rate_limit"]["requests_per_second"], 5)
        self.assertEqual(generated["required_headers"], {"X-Bug-Bounty": TEST_USERNAME})
        for gate in (
            "mutation_allowed",
            "sensitive_data_access_allowed",
            "credential_use_allowed",
            "pivoting_allowed",
            "availability_impact_allowed",
            "destructive_allowed",
        ):
            self.assertIs(generated[gate], False)

    def test_unrelated_api_metadata_is_never_copied_to_the_draft(self) -> None:
        program = json.loads(json.dumps(self.program))
        sentinel = "sensitive-sentinel-never-copy"
        program["privateMetadata"] = {"accessToken": sentinel}
        rendered = self.module.render_yaml(
            self.module.build_yaml(program, TEST_USERNAME, assume_yes=True)
        )
        self.assertNotIn(sentinel, rendered)

    def test_generated_yaml_round_trips_through_scope_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "engagement.yaml"
            path.write_text(yaml.safe_dump(self.generated(), sort_keys=False), encoding="utf-8")
            loaded = load_engagement(path)
        self.assertTrue(scope_decision(loaded, "account.here.com")[0])
        self.assertTrue(scope_decision(loaded, "a.account.here.com")[0])
        self.assertFalse(scope_decision(loaded, "here.com")[0])
        self.assertFalse(scope_decision(loaded, "here.com.evil.com")[0])
        self.assertFalse(scope_decision(loaded, "here.okta.com")[0])

    def test_cli_writes_draft_without_activating_or_overwriting(self) -> None:
        active = ROOT / ".active_engagement"
        active_before = active.read_bytes() if active.exists() else None
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "here"
            command = [
                sys.executable,
                str(SCRIPT),
                "heretechnologies/heretechnologies",
                "--username",
                TEST_USERNAME,
                "--from-file",
                str(FIXTURE),
                "--out",
                str(out),
                "--yes",
            ]
            first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            draft = out / "engagement.yaml"
            self.assertTrue(draft.is_file())
            self.assertEqual(stat.S_IMODE(draft.stat().st_mode), 0o600)
            self.assertIn("Draft engagement written", first.stdout)
            second = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("--force", second.stderr)
        active_after = active.read_bytes() if active.exists() else None
        self.assertEqual(active_after, active_before)

    def test_no_paying_tier_is_rejected(self) -> None:
        program = json.loads(json.dumps(self.program))
        latest = max(program["bountyTables"], key=lambda item: item["createdAt"])
        for row in latest["content"]["bountyRows"]:
            for bounty_range in row["bountyRanges"]:
                bounty_range["minBounty"]["value"] = 0
        with self.assertRaisesRegex(ValueError, "paying tier"):
            self.module.build_yaml(program, TEST_USERNAME, assume_yes=True)


if __name__ == "__main__":
    unittest.main()
