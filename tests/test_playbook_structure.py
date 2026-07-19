#!/usr/bin/env python3
"""Regression tests for the topic-module playbook interface."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"
LEGACY_DIRS = {"modern", "web", "code"}


def review_status(path: Path) -> str | None:
    match = re.search(
        r"(?m)^review_status:\s*[\"']?([^\"'\n]+)[\"']?\s*$",
        path.read_text(encoding="utf-8"),
    )
    return match.group(1).strip() if match else None


class PlaybookStructureTests(unittest.TestCase):
    def test_legacy_storage_layers_are_gone(self) -> None:
        for name in LEGACY_DIRS:
            self.assertFalse((PLAYBOOKS / name).exists(), name)

    def test_every_topic_has_one_readme_interface(self) -> None:
        topics = sorted(
            path
            for path in PLAYBOOKS.iterdir()
            if path.is_dir() and not path.name.startswith("_")
        )
        self.assertGreaterEqual(len(topics), 40)
        for topic in topics:
            self.assertTrue((topic / "README.md").is_file(), topic.name)

    def test_reviewed_and_imported_inventory_survives_migration(self) -> None:
        statuses = [
            review_status(path)
            for path in PLAYBOOKS.glob("*/*.md")
            if path.name != "README.md" or path.parent.name != "code-review"
        ]
        self.assertEqual(statuses.count("source-reviewed"), 48)
        self.assertEqual(statuses.count("imported-unreviewed"), 69)

    def test_topic_readmes_route_to_their_local_operator_references(self) -> None:
        for readme in sorted(PLAYBOOKS.glob("*/README.md")):
            if readme.parent.name == "code-review":
                continue
            references = sorted(
                path for path in readme.parent.glob("*.md") if path.name != "README.md"
            )
            text = readme.read_text(encoding="utf-8")
            for reference in references:
                self.assertIn(f"]({reference.name})", text, reference.as_posix())

    def test_root_catalog_is_the_single_routing_interface(self) -> None:
        catalogs = list(PLAYBOOKS.glob("**/_catalog.md"))
        self.assertEqual(catalogs, [PLAYBOOKS / "_catalog.md"])
        catalog = catalogs[0].read_text(encoding="utf-8")
        self.assertIn("graphql/README.md", catalog)
        self.assertIn("sql-injection/sqli-blind-sql-injection.md", catalog)
        self.assertIn("code-review/sinks-python.md", catalog)


if __name__ == "__main__":
    unittest.main()
