#!/usr/bin/env python3
"""Regression gate for the high-priority gaps identified by the 2026 audit."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODERN = ROOT / "playbooks" / "modern"
CODE = ROOT / "playbooks" / "code"

REQUIRED_MODERN = {
    "attack-surface-architecture-mapping.md",
    "external-resource-ownership.md",
    "transaction-integrity-payment-workflows.md",
    "realtime-sse-webrtc-authorization.md",
    "workload-nonhuman-identity-lifecycle.md",
    "browser-request-integrity-policy.md",
    "request-parameter-authority-differentials.md",
    "token-jose-verification-boundaries.md",
    "command-directory-entity-injection.md",
}
REQUIRED_CODE = {"sinks-csharp.md", "sinks-rust.md", "sinks-kotlin.md"}


class RecommendedCoverageTests(unittest.TestCase):
    def test_empty_import_indexes_are_retired_without_removing_depth(self) -> None:
        web = ROOT / "playbooks/web"
        for name in ("api-tools.md", "cloud.md", "cms.md", "http-attacks.md", "web-attacks.md"):
            self.assertFalse((web / name).exists(), name)
        for retained in (
            "api.md",
            "cloud-aws-cognito.md",
            "cms-wordpress.md",
            "http-attacks-request-smuggling-and-http-desync.md",
            "http-attacks-tls-attacks.md",
        ):
            self.assertTrue((web / retained).is_file(), retained)

    def test_reviewed_gap_cards_exist_and_follow_safe_contract(self) -> None:
        catalog = (MODERN / "_catalog.md").read_text(encoding="utf-8")
        for name in sorted(REQUIRED_MODERN):
            text = (MODERN / name).read_text(encoding="utf-8")
            self.assertIn(f"`{name}`", catalog, name)
            for section in (
                "## Threat model",
                "## Safe detection",
                "## Confirmation and evidence",
                "## Remediation",
                "## Sources",
            ):
                self.assertIn(section, text, name)
            sources = re.findall(r"\[[^]]+\]\(https://[^)]+\)", text.split("## Sources", 1)[1])
            self.assertGreaterEqual(len(sources), 2, name)

    def test_missing_language_sink_packs_are_routable(self) -> None:
        catalog = (CODE / "_catalog.md").read_text(encoding="utf-8")
        for name in sorted(REQUIRED_CODE):
            text = (CODE / name).read_text(encoding="utf-8")
            self.assertIn(name, catalog, name)
            self.assertIn("## Evidence contract", text, name)
            self.assertIn("## Remediation", text, name)
            self.assertIn("## Sources", text, name)

    def test_high_risk_imported_notes_bridge_to_focused_reviewed_cards(self) -> None:
        catalog = (ROOT / "playbooks/web/_catalog.md").read_text(encoding="utf-8")
        expected = {
            "csrf.md": "browser-request-integrity-policy.md",
            "cors.md": "browser-request-integrity-policy.md",
            "jwt.md": "token-jose-verification-boundaries.md",
            "parameter-pollution.md": "request-parameter-authority-differentials.md",
            "http-attacks-host-header.md": "request-parameter-authority-differentials.md",
            "http-attacks-crlf-injection-and-response-splitting.md": "request-parameter-authority-differentials.md",
            "os-command-injection.md": "command-directory-entity-injection.md",
            "ldap-injections.md": "command-directory-entity-injection.md",
            "xxe.md": "command-directory-entity-injection.md",
        }
        for note, card in expected.items():
            self.assertIn(f"| `{note}` | `../modern/{card}` |", catalog)

    def test_readme_describes_current_knowledge_and_loop_state(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("lead-state.json", readme)
        self.assertIn("48 source-reviewed", readme)
        self.assertIn("69 imported", readme)
        self.assertNotIn("83 imported", readme)


if __name__ == "__main__":
    unittest.main()
