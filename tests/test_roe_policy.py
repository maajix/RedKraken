#!/usr/bin/env python3
"""Rules-of-engagement authorization policy tests using synthetic fixtures."""

from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import harness_config  # noqa: E402


ConfigError = harness_config.ConfigError
load_engagement = harness_config.load_engagement


GATES = (
    "mutation_allowed",
    "sensitive_data_access_allowed",
    "credential_use_allowed",
    "pivoting_allowed",
    "availability_impact_allowed",
)


class RoeAuthorizationTests(unittest.TestCase):
    def policy(self, config: dict) -> dict:
        helper = getattr(harness_config, "roe_authorizations", None)
        self.assertTrue(callable(helper), "roe_authorizations helper is missing")
        return helper(config)

    def load(self, extra: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "engagement.yaml"
            path.write_text(
                "targets:\n  - app.example.test\nout_of_scope: []\n" + extra,
                encoding="utf-8",
            )
            return load_engagement(path)

    def test_legacy_destructive_gate_only_falls_back_to_mutation(self) -> None:
        policy = self.policy(self.load("destructive_allowed: true\n"))
        self.assertEqual(
            policy,
            {
                "mutation_allowed": True,
                "sensitive_data_access_allowed": False,
                "credential_use_allowed": False,
                "pivoting_allowed": False,
                "availability_impact_allowed": False,
            },
        )

    def test_explicit_gates_override_legacy_fallback_and_remain_independent(self) -> None:
        config = self.load(
            "destructive_allowed: true\n"
            "mutation_allowed: false\n"
            "sensitive_data_access_allowed: true\n"
            "credential_use_allowed: true\n"
            "pivoting_allowed: false\n"
            "availability_impact_allowed: true\n"
        )
        self.assertEqual(
            self.policy(config),
            {
                "mutation_allowed": False,
                "sensitive_data_access_allowed": True,
                "credential_use_allowed": True,
                "pivoting_allowed": False,
                "availability_impact_allowed": True,
            },
        )

    def test_all_gates_default_to_false_when_unspecified(self) -> None:
        self.assertEqual(self.policy(self.load("")), {gate: False for gate in GATES})

    def test_policy_helper_fails_closed_for_unvalidated_non_boolean_values(self) -> None:
        policy = self.policy({"destructive_allowed": True, "mutation_allowed": "false"})
        self.assertFalse(policy["mutation_allowed"])

    def test_each_gate_requires_a_boolean(self) -> None:
        for gate in GATES:
            with self.subTest(gate=gate):
                with self.assertRaisesRegex(ConfigError, f"{gate} must be true or false"):
                    self.load(f"{gate}: yes-please\n")

    def test_raw_egress_self_contained_requires_a_boolean(self) -> None:
        with self.assertRaisesRegex(
            ConfigError, "raw_egress_self_contained must be true or false"
        ):
            self.load("raw_egress_self_contained: yes-please\n")

    def test_example_and_agent_guidance_name_every_independent_gate(self) -> None:
        documents = [
            ROOT / "scope" / "engagement.example.yaml",
            ROOT / ".claude" / "agents" / "exploit-agent.md",
            ROOT / ".claude" / "skills" / "ssrf-xxe-file" / "SKILL.md",
        ]
        for document in documents:
            text = document.read_text(encoding="utf-8")
            with self.subTest(document=document):
                for gate in GATES:
                    self.assertIn(gate, text)

    def test_example_fails_closed_without_real_identifiers_or_credentials(self) -> None:
        text = (ROOT / "scope" / "engagement.example.yaml").read_text(encoding="utf-8")
        for gate in GATES:
            self.assertIn(f"{gate}: false", text)
        self.assertNotIn("169.254.169.254", text)
        self.assertNotRegex(text, r"(?i)(api[_-]?key|access[_-]?token|secret)\s*:\s*[^<\s][^\n]*")

    def test_mutating_wrapper_uses_resolved_policy_not_legacy_flag_directly(self) -> None:
        text = (ROOT / "scripts" / "run_schemathesis.sh").read_text(encoding="utf-8")
        self.assertIn("roe_authorizations", text)
        self.assertIn('policy["mutation_allowed"]', text)
        self.assertNotIn('config.get("destructive_allowed")', text)

    def test_orchestration_contracts_name_the_independent_gates(self) -> None:
        documents = [
            ROOT / ".claude/skills/scope-guard/SKILL.md",
            ROOT / ".claude/skills/api-stateful/SKILL.md",
            ROOT / ".claude/skills/web-pentest-loop/SKILL.md",
            ROOT / ".claude/skills/code-audit-loop/SKILL.md",
        ]
        for document in documents:
            text = document.read_text(encoding="utf-8")
            with self.subTest(document=document):
                self.assertIn("mutation_allowed", text)
                self.assertIn("sensitive_data_access_allowed", text)
                self.assertIn("credential_use_allowed", text)
                self.assertIn("pivoting_allowed", text)
                self.assertIn("availability_impact_allowed", text)

    def test_required_headers_are_string_only_and_injection_safe(self) -> None:
        valid = self.load("required_headers:\n  X-Bug-Bounty: synthetic-tester\n")
        self.assertEqual(valid["required_headers"], {"X-Bug-Bounty": "synthetic-tester"})
        for fragment in (
            "required_headers: []\n",
            "required_headers:\n  Bad Header: value\n",
            "required_headers:\n  X-Test: 123\n",
            'required_headers:\n  X-Test: "safe\\nInjected: value"\n',
        ):
            with self.subTest(fragment=fragment):
                with self.assertRaises(ConfigError):
                    self.load(fragment)

    def test_per_tool_rate_policy_can_only_tighten_global_limits(self) -> None:
        config = self.load(
            "rate_limit_enabled: true\n"
            "rate_limit:\n"
            "  requests_per_second: 5\n"
            "  burst: 5\n"
            "  max_concurrency: 2\n"
            "  per_tool:\n"
            "    nuclei:\n"
            "      requests_per_second: 20\n"
            "      burst: 10\n"
            "      max_concurrency: 8\n"
        )
        self.assertEqual(
            harness_config.rate_policy(config, "nuclei"),
            {"requests_per_second": 5.0, "burst": 5, "max_concurrency": 2},
        )

    def test_proxy_request_contract_serializes_work_and_applies_headers(self) -> None:
        documents = {
            "loop": ROOT / ".claude/skills/web-pentest-loop/SKILL.md",
            "hunter": ROOT / ".claude/agents/web-vuln-hunter.md",
            "recon": ROOT / ".claude/agents/recon-agent.md",
            "scope": ROOT / ".claude/skills/scope-guard/SKILL.md",
        }
        text = {
            name: " ".join(path.read_text(encoding="utf-8").casefold().split())
            for name, path in documents.items()
        }
        self.assertIn("dispatch one family at a time", text["loop"])
        self.assertIn("required_headers", text["loop"])
        self.assertIn("scripts/run_scoped_http.sh", text["loop"])
        for name in ("hunter", "recon"):
            with self.subTest(document=name):
                self.assertIn("required_headers", text[name])
                self.assertIn("one target-touching tool", text[name])
                self.assertIn("scripts/run_scoped_http.sh", text[name])
                self.assertIn("not-tested", text[name])
        self.assertIn("required_headers", text["scope"])
        self.assertIn("one worker", text["scope"])
        self.assertIn("no_proxy", text["scope"])


if __name__ == "__main__":
    unittest.main()
