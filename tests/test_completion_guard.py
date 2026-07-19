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

    def test_unknown_subagent_type_is_not_blocked(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_type": "reporter",
                "last_assistant_message": "Done.",
            }
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


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
            "recon-agent|web-vuln-hunter",
        )


if __name__ == "__main__":
    unittest.main()
