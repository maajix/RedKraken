#!/usr/bin/env python3
"""Static contract tests for autonomous-loop routing.

These tests inspect repository instructions and metadata only. They never open an
engagement directory or contain target-specific data.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FAMILY_ROOT = ROOT / ".claude" / "skills" / "families"
REGISTRY = FAMILY_ROOT / "registry.json"
SCENARIOS = ROOT / "playbooks" / "_meta" / "scenario-baselines.json"


class LoopContractTests(unittest.TestCase):
    def test_family_registry_covers_every_loadable_family(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        rows = registry["families"]
        actual = {
            path.parent.name
            for path in FAMILY_ROOT.glob("*/SKILL.md")
        }
        self.assertEqual({row["family"] for row in rows}, actual)
        self.assertEqual(len(rows), len(actual))

        required = {
            "family",
            "skill",
            "triggers",
            "prerequisites",
            "playbooks",
            "fixture_requirements",
            "positive_evidence",
            "negative_evidence",
            "safety_class",
            "follow_on_families",
        }
        for row in rows:
            self.assertEqual(required - row.keys(), set(), row["family"])
            self.assertTrue(row["triggers"], row["family"])
            self.assertTrue(row["playbooks"], row["family"])
            self.assertLessEqual(set(row["follow_on_families"]), actual, row["family"])
            for playbook in row["playbooks"]:
                self.assertTrue((ROOT / playbook).is_file(), playbook)
        routed = {path for row in rows for path in row["playbooks"]}
        self.assertLessEqual(
            {
                "playbooks/attack-surface/README.md",
                "playbooks/external-resources/README.md",
                "playbooks/payment-workflows/README.md",
                "playbooks/realtime/README.md",
                "playbooks/workload-identities/README.md",
                "playbooks/request-integrity/README.md",
                "playbooks/request-parsing/README.md",
                "playbooks/jwt-jose/README.md",
                "playbooks/command-directory-injection/README.md",
            },
            routed,
        )

    def test_recon_contract_is_delta_driven_and_bounded(self) -> None:
        command = (ROOT / ".claude/commands/recon.md").read_text(encoding="utf-8")
        skill = (ROOT / ".claude/skills/web-recon/SKILL.md").read_text(encoding="utf-8")
        agent = (ROOT / ".claude/agents/recon-agent.md").read_text(encoding="utf-8")
        combined = "\n".join((command, skill, agent)).casefold()
        for phrase in (
            "surface delta",
            "no-progress",
            "round budget",
            "scripts/lead_state.py",
            "coverage ledger",
        ):
            self.assertIn(phrase, combined)

    def test_pentest_contract_retriages_derived_leads_until_convergence(self) -> None:
        loop = (ROOT / ".claude/skills/web-pentest-loop/SKILL.md").read_text(
            encoding="utf-8"
        ).casefold()
        hunter = " ".join(
            (ROOT / ".claude/agents/web-vuln-hunter.md")
            .read_text(encoding="utf-8")
            .casefold()
            .split()
        )
        for phrase in (
            "derived leads",
            "re-triage",
            "coverage ledger",
            "two no-progress rounds",
            "scripts/lead_state.py",
            "actionable",
            "lead-state.json",
            "--max-requests",
            "--max-seconds",
        ):
            self.assertIn(phrase, loop)
        self.assertNotIn("leads.jsonl", loop)
        self.assertIn("derived leads", hunter)
        self.assertIn("negative evidence", hunter)

    def test_pentest_contract_separates_dispatch_from_derived_lead_handoff(self) -> None:
        loop = (ROOT / ".claude/skills/web-pentest-loop/SKILL.md").read_text(
            encoding="utf-8"
        ).casefold()
        hunter = " ".join(
            (ROOT / ".claude/agents/web-vuln-hunter.md")
            .read_text(encoding="utf-8")
            .casefold()
            .split()
        )

        self.assertIn("lease <lead-id>", loop)
        self.assertIn("never claim unrelated queued work", loop)
        self.assertIn("leave derived leads queued", hunter)
        self.assertIn("do not lease a derived lead", hunter)

    def test_scenario_baselines_are_immutable_and_required_by_loop(self) -> None:
        manifest = json.loads(SCENARIOS.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(
            {row["id"] for row in manifest["baselines"]},
            {"owasp-wstg-v42-scenarios", "owasp-asvs-v5.0.0-requirements"},
        )
        for row in manifest["baselines"]:
            self.assertRegex(row["source"], r"^https://")
            self.assertTrue(row["versioned_id_pattern"])
            self.assertTrue(row["version"])
        loop = (ROOT / ".claude/skills/web-pentest-loop/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("scenario-baselines.json", loop)
        self.assertIn("versioned scenario", loop.casefold())

    def test_subagent_summaries_match_completion_hook_contract(self) -> None:
        for relative in (
            ".claude/agents/recon-agent.md",
            ".claude/agents/web-vuln-hunter.md",
        ):
            instructions = (ROOT / relative).read_text(encoding="utf-8")
            for heading in (
                "Host count",
                "Endpoint count",
                "Confirmed findings",
                "Suspected findings",
            ):
                self.assertIn(heading, instructions, relative)


if __name__ == "__main__":
    unittest.main()
