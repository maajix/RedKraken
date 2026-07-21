#!/usr/bin/env python3
"""Contract tests for the deterministic Stop/SubagentStop completion guard.

All fixtures are synthetic and live in temporary directories.  The tests do
not resolve or inspect the repository's active engagement.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / ".claude" / "hooks" / "completion_guard.py"
SETTINGS = ROOT / ".claude" / "settings.json"
sys.path.insert(0, str(ROOT / "lib"))
from lead_store import LeadState  # noqa: E402


class CompletionGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name) / "project"
        self.engagement = Path(self.temporary.name) / "synthetic-engagement"
        (self.project / ".active_engagement").parent.mkdir(parents=True)
        (self.engagement / "state").mkdir(parents=True)
        (self.project / ".active_engagement").write_text(
            str(self.engagement) + "\n", encoding="utf-8"
        )
        # By default the synthetic Stop session owns the engagement, so the
        # existing Stop-gate contract tests exercise the can_stop logic.  The
        # owner-scoping tests below override or clear this marker.
        self.owner_marker = self.engagement / "state" / "completion-guard-owner.json"
        self.own_engagement("session-synthetic-001")

    def own_engagement(self, session_id: str) -> None:
        self.owner_marker.write_text(
            json.dumps({"session_id": session_id}), encoding="utf-8"
        )

    def clear_owner(self) -> None:
        self.owner_marker.unlink(missing_ok=True)

    def write_state(
        self,
        *,
        status: str = "queued",
        iteration: int = 0,
        max_iterations: int = 4,
        no_progress_rounds: int = 0,
        max_no_progress_rounds: int = 2,
    ) -> None:
        store = LeadState(self.engagement, clock=lambda: "2026-01-01T00:00:00Z")
        store.configure_loop(
            max_iterations=max_iterations,
            max_no_progress_rounds=max_no_progress_rounds,
            max_attempts=3,
        )
        inserted = store.upsert_lead(
            {
                "family": "access-control",
                "kind": "endpoint",
                "subject": "https://app.example.test/items/7",
                "method": "GET",
                "parameter": "item_id",
                "priority": 80,
                "provenance": ["PRIVATE_MARKER_DO_NOT_ECHO"],
                "evidence": ["observation:synthetic"],
            }
        )
        if status == "completed":
            store.lease_next("worker-synthetic")
            store.complete_lead(
                inserted["lead"]["id"], "worker-synthetic", "completed"
            )
        for _ in range(iteration):
            store.record_iteration(progress=True)
        for _ in range(no_progress_rounds):
            store.record_iteration(progress=False)

    def run_hook(self, payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
        hook_input = {
            "session_id": "session-synthetic-001",
            "cwd": str(self.project),
            "hook_event_name": "Stop",
            "stop_hook_active": False,
            **payload,
        }
        env = os.environ.copy()
        env.pop("PENTEST_ENGAGEMENT_DIR", None)
        return subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            check=False,
            env=env,
            timeout=5,
        )

    def test_stop_blocks_when_actionable_lead_and_budget_remain(self) -> None:
        self.write_state()
        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["decision"], "block")
        self.assertIn("Actionable pentest work remains", output["reason"])
        self.assertNotIn("PRIVATE_MARKER_DO_NOT_ECHO", result.stdout + result.stderr)

    def test_stop_allows_when_iteration_budget_is_exhausted(self) -> None:
        self.write_state(iteration=4, max_iterations=4)
        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_stop_allows_when_no_actionable_lead_remains(self) -> None:
        self.write_state(status="completed")
        LeadState(self.engagement).record_coverage(
            "family", "access-control", "tested"
        )
        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_stop_blocks_when_required_coverage_has_no_queued_lead(self) -> None:
        store = LeadState(self.engagement, clock=lambda: "2026-01-01T00:00:00Z")
        store.record_coverage(
            "workflow",
            "asset=synthetic.example.test;method=crawl;role=anonymous",
            "not-tested",
            reason="required discovery pending",
        )

        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["decision"], "block")
        self.assertIn("completion requirements remain", output["reason"].casefold())

    def test_stop_hook_active_never_blocks_again(self) -> None:
        self.write_state()
        result = self.run_hook({"stop_hook_active": True})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_malformed_state_fails_open_without_echoing_content(self) -> None:
        (self.engagement / "state" / "lead-state.json").write_text(
            '{"private":"PRIVATE_MARKER_DO_NOT_ECHO",', encoding="utf-8"
        )
        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("PRIVATE_MARKER_DO_NOT_ECHO", result.stderr)

    def test_recon_subagent_requires_machine_checkable_summary_headings(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "recon-agent",
                "last_assistant_message": "Recon finished.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertNotIn("Recon finished", result.stdout + result.stderr)

    def test_recon_subagent_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "recon-agent",
                "last_assistant_message": (
                    "Host count: 1\nEndpoint count: 4\nEnvironment facts\n"
                    "No additional context."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_hunter_subagent_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "web-vuln-hunter",
                "last_assistant_message": (
                    "Confirmed findings: 0\nSuspected findings: 1\n"
                    "Environment facts\nSynthetic test only."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_bypass_specialist_requires_machine_checkable_summary_headings(
        self,
    ) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "bypass-specialist",
                "last_assistant_message": "Bypass attempted, no luck.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertNotIn("Bypass attempted", result.stdout + result.stderr)

    def test_bypass_specialist_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "bypass-specialist",
                "last_assistant_message": (
                    "Bypass outcome: not bypassed under the tested matrix\n"
                    "Transformation classes tested: encoding, casing\n"
                    "Residual controls: WAF normalization intact\n"
                    "Environment facts\nSynthetic test only."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_code_auditor_requires_machine_checkable_summary_fields(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "code-auditor",
                "last_assistant_message": "Audit finished.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertNotIn("Audit finished", result.stdout + result.stderr)

    def test_code_auditor_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "code-auditor",
                "last_assistant_message": (
                    "Confirmed: 1 finding. Suspected: 0 findings.\n"
                    "Environment facts\nSynthetic test only."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_exploit_agent_requires_machine_checkable_summary_fields(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "exploit-agent",
                "last_assistant_message": "Exploit finished.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertNotIn("Exploit finished", result.stdout + result.stderr)

    def test_exploit_agent_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "exploit-agent",
                "last_assistant_message": (
                    "Impact: SQLi dumped a synthetic canary row.\n"
                    "RoE gates: none blocking.\nSynthetic test only."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_exploit_agent_accepts_gate_blocked_terminal_state(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "exploit-agent",
                "last_assistant_message": (
                    "Impact: exploitable-not-detonated; least-sensitive "
                    "current_user read-only proof only.\n"
                    "RoE gates: mutation_allowed and credential_use_allowed are "
                    "false and block escalation."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_reporter_requires_machine_checkable_summary_fields(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "reporter",
                "last_assistant_message": "Report written.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertNotIn("Report written", result.stdout + result.stderr)

    def test_reporter_accepts_contract_summary(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "reporter",
                "last_assistant_message": (
                    "Report path: engagements/1/report.md\n"
                    "Severity counts: critical 1, high 2.\n"
                    "Coverage gaps: none.\nSynthetic test only."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_reporter_accepts_zero_findings_terminal_state(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "reporter",
                "last_assistant_message": (
                    "Report path: engagements/1/report.md\n"
                    "Severity counts: 0 across all severities.\n"
                    "Coverage gaps: workflow family not tested."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_unknown_subagent_type_is_not_blocked(self) -> None:
        # An explorer lens is deliberately excluded from the Stop-text guard;
        # its output contract is enforced coordinator-side, not here.
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "surface-archaeologist",
                "last_assistant_message": "Done.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_target_subagent_stop_records_owner_session(self) -> None:
        self.clear_owner()
        result = self.run_hook(
            {
                "session_id": "session-owner-xyz",
                "hook_event_name": "SubagentStop",
                "agent_type": "recon-agent",
                "last_assistant_message": (
                    "Host count: 1\nEndpoint count: 4\nEnvironment facts\nok."
                ),
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(self.owner_marker.is_file())
        recorded = json.loads(self.owner_marker.read_text(encoding="utf-8"))
        self.assertEqual(recorded["session_id"], "session-owner-xyz")

    def test_non_target_subagent_stop_does_not_record_owner(self) -> None:
        self.clear_owner()
        result = self.run_hook(
            {
                "session_id": "session-explorer",
                "hook_event_name": "SubagentStop",
                "agent_type": "surface-archaeologist",
                "last_assistant_message": "Done.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.owner_marker.exists())

    def test_stop_from_non_owner_session_passes_through(self) -> None:
        # Actionable lead + budget would block the owner, but this Stop is from
        # an unrelated session working in the same repo -- it must pass through.
        self.write_state()
        result = self.run_hook({"session_id": "session-unrelated-999"})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_stop_without_recorded_owner_passes_through(self) -> None:
        self.clear_owner()
        self.write_state()
        result = self.run_hook({})

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_owner_recorded_by_subagent_then_only_owner_stop_is_validated(
        self,
    ) -> None:
        self.clear_owner()
        self.write_state()
        self.run_hook(
            {
                "session_id": "session-owner-xyz",
                "hook_event_name": "SubagentStop",
                "agent_type": "recon-agent",
                "last_assistant_message": (
                    "Host count: 1\nEndpoint count: 4\nEnvironment facts\nok."
                ),
            }
        )

        owned = self.run_hook({"session_id": "session-owner-xyz"})
        self.assertEqual(json.loads(owned.stdout)["decision"], "block")

        other = self.run_hook({"session_id": "session-different"})
        self.assertEqual(other.stdout, "")


class HookWiringTest(unittest.TestCase):
    def test_stop_hooks_are_wired_to_completion_guard(self) -> None:
        settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        for event in ("Stop", "SubagentStop"):
            groups = settings["hooks"][event]
            commands = [
                hook["command"]
                for group in groups
                for hook in group["hooks"]
                if hook.get("type") == "command"
            ]
            self.assertEqual(
                commands,
                ["$CLAUDE_PROJECT_DIR/.claude/hooks/completion_guard_hook.sh"],
            )
        self.assertEqual(
            settings["hooks"]["SubagentStop"][0]["matcher"],
            "recon-agent|web-vuln-hunter|bypass-specialist|code-auditor"
            "|exploit-agent|reporter",
        )


if __name__ == "__main__":
    unittest.main()
