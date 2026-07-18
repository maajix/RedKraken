#!/usr/bin/env python3
"""Tests for bounded, secret-filtering target-derived wordlists."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_recon_wordlist.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_recon_wordlist", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReconWordlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "capture.html"
        self.jwt = "eyJfixture.segment.signaturefixture"
        self.source.write_text(
            '<a href="https://app.example.test/admin/config?token=query-secret">Admin Config</a> '
            "WordPress backup owner@example.test "
            f"Authorization: Bearer {self.jwt} "
            "550e8400-e29b-41d4-a716-446655440000 "
            "f4e3d2c1b0a9988776655443322110ffeeddccbb"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_builds_backup_candidates_without_sensitive_tokens(self) -> None:
        module = load_module()
        words, metadata = module.build_wordlist([self.source], max_entries=100, per_source=50)
        self.assertIn("admin", words)
        self.assertIn("config", words)
        self.assertIn("config.bak", words)
        self.assertIn("wordpress", words)
        rendered = "\n".join(words)
        for forbidden in ("query-secret", self.jwt, "owner", "550e8400", "f4e3d2c1"):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(metadata[0]["sha256"], module.sha256_file(self.source))
        self.assertNotIn("content", metadata[0])

    def test_bounds_per_source_total_and_token_length(self) -> None:
        noisy = self.root / "noisy.txt"
        noisy.write_text(" ".join(f"word{number}" for number in range(200)) + " " + "x" * 100)
        words, _ = load_module().build_wordlist([noisy], max_entries=12, per_source=8, max_token_length=32)
        self.assertLessEqual(len(words), 12)
        self.assertTrue(all(len(word) <= 32 for word in words))

    def test_write_uses_0600_and_hash_only_metadata(self) -> None:
        module = load_module()
        output = self.root / "state" / "recon-words.txt"
        meta = module.write_wordlist([self.source], output, max_entries=30, per_source=20)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(meta).st_mode & 0o777, 0o600)
        metadata = json.loads(meta.read_text())
        self.assertNotIn(self.jwt, json.dumps(metadata))
        self.assertEqual(metadata["output_sha256"], module.sha256_file(output))


if __name__ == "__main__":
    unittest.main()
