#!/usr/bin/env python3
"""Behavior tests for tamper-evident audit JSONL."""

from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from audit_event import append_event, event_from_hook  # noqa: E402

VERIFY_PATH = ROOT / "scripts" / "verify_audit.py"
TOKEN_PLACEHOLDER = "<SYNTHETIC_TOKEN_NOT_A_CREDENTIAL>"
SENSITIVE_PLACEHOLDER = "<SYNTHETIC_SENSITIVE_VALUE>"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_audit", VERIFY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def append_worker(directory: str, number: int) -> None:
    append_event(Path(directory), {
        "schema_version": 1, "event": "worker", "number": number,
    })


class AuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "engagement"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def events(self) -> list[dict]:
        return [json.loads(line) for line in (self.directory / "audit.jsonl").read_text().splitlines()]

    def verify(self):
        return load_verifier().verify_path(self.directory / "audit.jsonl")

    def test_genesis_and_multi_event_chain_verify(self) -> None:
        append_event(self.directory, {"schema_version": 1, "event": "first"})
        append_event(self.directory, {"schema_version": 1, "event": "second"})
        events = self.events()
        self.assertEqual(events[0]["prev_sha256"], "0" * 64)
        self.assertEqual(events[1]["prev_sha256"], events[0]["event_sha256"])
        self.assertTrue(all(event["audit_chain_version"] == 1 for event in events))
        result = self.verify()
        self.assertTrue(result.valid, result.reason)
        self.assertEqual(result.legacy_prefix, 0)

    def test_legacy_prefix_is_anchored_without_rewriting_it(self) -> None:
        self.directory.mkdir(mode=0o700)
        legacy = {"schema_version": 1, "event": "legacy", "command": "safe"}
        (self.directory / "audit.jsonl").write_text(json.dumps(legacy) + "\n")
        append_event(self.directory, {"schema_version": 1, "event": "new"})
        events = self.events()
        self.assertEqual(events[0], legacy)
        self.assertEqual(events[1]["chain_origin"], "legacy-anchor")
        result = self.verify()
        self.assertTrue(result.valid, result.reason)
        self.assertEqual(result.legacy_prefix, 1)

    def test_changed_event_reports_first_broken_line_without_content(self) -> None:
        append_event(self.directory, {
            "schema_version": 1, "event": "alpha", "secret": SENSITIVE_PLACEHOLDER,
        })
        append_event(self.directory, {"schema_version": 1, "event": "beta"})
        lines = (self.directory / "audit.jsonl").read_text().splitlines()
        changed = json.loads(lines[0])
        changed["event"] = "changed"
        lines[0] = json.dumps(changed)
        (self.directory / "audit.jsonl").write_text("\n".join(lines) + "\n")
        result = self.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.line, 1)
        self.assertNotIn(SENSITIVE_PLACEHOLDER, result.reason)

    def test_removed_inserted_duplicated_and_reordered_lines_are_rejected(self) -> None:
        for number in range(4):
            append_event(self.directory, {"schema_version": 1, "event": "item", "number": number})
        original = (self.directory / "audit.jsonl").read_text().splitlines()
        variants = [
            original[:1] + original[2:],
            original[:2] + [original[0]] + original[2:],
            original[:2] + [original[1]] + original[2:],
            [original[1], original[0], *original[2:]],
        ]
        for lines in variants:
            with self.subTest(lines=len(lines)):
                (self.directory / "audit.jsonl").write_text("\n".join(lines) + "\n")
                self.assertFalse(self.verify().valid)
        (self.directory / "audit.jsonl").write_text("\n".join(original) + "\n")

    def test_truncated_json_and_malformed_tail_refuse_extension(self) -> None:
        append_event(self.directory, {"schema_version": 1, "event": "good"})
        path = self.directory / "audit.jsonl"
        with path.open("a") as handle:
            handle.write('{"event":"partial"')
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "malformed audit tail"):
            append_event(self.directory, {"schema_version": 1, "event": "refused"})
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(self.verify().valid)

    def test_concurrent_writers_form_one_linear_chain(self) -> None:
        processes = [multiprocessing.Process(target=append_worker, args=(str(self.directory), n)) for n in range(60)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(len(self.events()), 60)
        self.assertTrue(self.verify().valid)

    def test_modes_and_redaction_precede_hashing(self) -> None:
        hook = event_from_hook({
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {
                "command": f"client --header 'Authorization: Bearer {TOKEN_PLACEHOLDER}' https://example.test"
            },
        })
        append_event(self.directory, hook)
        event = self.events()[0]
        self.assertNotIn(TOKEN_PLACEHOLDER, json.dumps(event))
        self.assertEqual(os.stat(self.directory).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.directory / "audit.jsonl").st_mode & 0o777, 0o600)
        self.assertTrue(self.verify().valid)

    def test_cli_exit_codes_and_safe_diagnostic(self) -> None:
        append_event(self.directory, {"schema_version": 1, "event": "ok"})
        good = subprocess.run([sys.executable, str(VERIFY_PATH), str(self.directory / "audit.jsonl")], text=True, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        (self.directory / "audit.jsonl").write_text("not-json\n")
        bad = subprocess.run([sys.executable, str(VERIFY_PATH), str(self.directory / "audit.jsonl")], text=True, capture_output=True)
        self.assertEqual(bad.returncode, 1)
        self.assertNotIn("not-json", bad.stdout + bad.stderr)
        missing = subprocess.run([sys.executable, str(VERIFY_PATH), str(self.directory / "missing.jsonl")], text=True, capture_output=True)
        self.assertEqual(missing.returncode, 2)

    def test_cli_can_assert_expected_legacy_prefix(self) -> None:
        self.directory.mkdir(mode=0o700)
        (self.directory / "audit.jsonl").write_text('{"schema_version":1,"event":"legacy"}\n')
        append_event(self.directory, {"schema_version": 1, "event": "new"})
        good = subprocess.run([
            sys.executable, str(VERIFY_PATH), "--expected-legacy-prefix", "1",
            str(self.directory / "audit.jsonl"),
        ], text=True, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        bad = subprocess.run([
            sys.executable, str(VERIFY_PATH), "--expected-legacy-prefix", "0",
            str(self.directory / "audit.jsonl"),
        ], text=True, capture_output=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("legacy prefix mismatch", bad.stdout)


if __name__ == "__main__":
    unittest.main()
