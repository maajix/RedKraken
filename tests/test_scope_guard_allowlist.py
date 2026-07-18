#!/usr/bin/env python3
"""Keep Claude's Bash allowlist aligned with the static scope guard."""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GUARD_PATH = ROOT / ".claude" / "hooks" / "scope_guard.py"
SPEC = importlib.util.spec_from_file_location("scope_guard", GUARD_PATH)
assert SPEC and SPEC.loader
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)

BASH_ALLOW_RE = re.compile(r"^Bash\(([^:*()]+):\*\)$")
KNOWN_TARGET_CAPABLE = {
    "amass", "curl", "dalfox", "dnsx", "feroxbuster", "ffuf", "gau",
    "gobuster", "grpcurl", "httpx", "katana", "mitmdump", "nikto", "nmap",
    "nuclei", "openssl", "paramspider", "playwright", "schemathesis", "sqlmap",
    "subfinder", "wafw00f", "waybackurls", "wget", "whatweb", "wpscan", "zaproxy",
}


def allowed_tools(settings: dict) -> set[str]:
    result: set[str] = set()
    for entry in settings.get("permissions", {}).get("allow", []):
        if not isinstance(entry, str):
            continue
        match = BASH_ALLOW_RE.fullmatch(entry)
        if match:
            result.add(match.group(1))
    return result


def uncovered(settings: dict, target_capable: set[str]) -> set[str]:
    allowed = allowed_tools(settings)
    exemptions = GUARD.NETWORK_TOOL_EXEMPTIONS
    return {
        tool for tool in allowed & target_capable
        if tool not in GUARD.NETWORK_TOOLS and tool not in exemptions
    }


class ScopeGuardAllowlistTests(unittest.TestCase):
    def test_current_target_tools_are_guarded_or_reasoned_exemptions(self) -> None:
        settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
        self.assertEqual(uncovered(settings, KNOWN_TARGET_CAPABLE), set())
        self.assertEqual(set(GUARD.NETWORK_TOOL_EXEMPTIONS), {"jwt-tool", "playwright", "zaproxy"})
        for reason in GUARD.NETWORK_TOOL_EXEMPTIONS.values():
            self.assertIsInstance(reason, str)
            self.assertGreaterEqual(len(reason.strip()), 12)

    def test_new_target_capable_allow_entry_fails_closed(self) -> None:
        fixture = {"permissions": {"allow": ["Bash(newnet:*)"]}}
        self.assertEqual(uncovered(fixture, {"newnet"}), {"newnet"})

    def test_parser_ignores_wrappers_and_local_processors(self) -> None:
        fixture = {"permissions": {"allow": [
            "Bash(jq:*)", "Bash(python3:*)", "Bash(./scripts/*)", "Read",
        ]}}
        self.assertEqual(allowed_tools(fixture), {"jq", "python3"})


if __name__ == "__main__":
    unittest.main()
