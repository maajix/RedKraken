#!/usr/bin/env python3
"""Regression tests for Claude Code project-skill discovery."""

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / ".claude" / "skills"
REGISTRY = SKILLS_DIR / "families" / "registry.json"


def direct_skill_names() -> set[str]:
    names = set()
    for skill_file in SKILLS_DIR.glob("*/SKILL.md"):
        frontmatter = skill_file.read_text(encoding="utf-8").split("---", 2)[1]
        match = re.search(r"^name:\s*(\S+)\s*$", frontmatter, re.MULTILINE)
        if match:
            names.add(match.group(1))
    return names


class SkillDiscoveryTests(unittest.TestCase):
    def test_registered_family_skills_are_directly_discoverable(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        registered = {entry["skill"] for entry in registry["families"]}

        self.assertSetEqual(registered - direct_skill_names(), set())


if __name__ == "__main__":
    unittest.main()
