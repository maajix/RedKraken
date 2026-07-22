#!/usr/bin/env python3
"""CLI regression test for finding JSON supplied through stdin markers."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "lib" / "finding_store.py"


class FindingStoreCliTests(unittest.TestCase):
    def test_stdin_markers_read_json_from_stdin(self) -> None:
        finding = json.dumps(
            {
                "id": "SYNTHETIC-1",
                "technique": "synthetic",
                "family": "test",
                "severity": "info",
                "status": "suspected",
                "summary": "synthetic fixture",
                "endpoint": "https://app.example.test/",
            }
        )
        for marker in ("-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(
                    [sys.executable, str(CLI), marker, "--engagement", directory],
                    input=finding,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "appended")


if __name__ == "__main__":
    unittest.main()
