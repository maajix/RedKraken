#!/usr/bin/env python3
"""Deterministic completion guard for autonomous pentest loops.

The hook reasons over the durable lead-state contract and, for `/full-pentest`,
the coordinator's final report gate. It never prints lead content, paths, parser
errors, or engagement data. Invalid/missing state is non-blocking so a damaged
hook cannot trap Claude in an endless Stop loop.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MAX_INPUT_BYTES = 64 * 1024
MAX_POINTER_BYTES = 4096
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_OWNER_BYTES = 4096
MAX_RUN_BYTES = 1024 * 1024
OWNER_MARKER_NAME = "completion-guard-owner.json"
TARGET_SUBAGENTS = {
    "recon-agent",
    "web-vuln-hunter",
    "bypass-specialist",
    "code-auditor",
    "exploit-agent",
    "reporter",
}


def _read_input() -> dict[str, Any] | None:
    raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def _block(reason: str) -> None:
    # Keep output deliberately generic: hook responses are model-visible.
    print(json.dumps({"decision": "block", "reason": reason}))


def _agent_type(payload: dict[str, Any]) -> str:
    for key in ("agent_type", "agent_name", "subagent_type"):
        value = payload.get(key)
        if isinstance(value, str):
            return value.strip().lower()
    return ""


def _valid_subagent_summary(agent_type: str, message: Any) -> bool:
    if not isinstance(message, str) or len(message) > MAX_INPUT_BYTES:
        return False
    summary = message.casefold()
    # The `environment facts` block is only documented for the four agents that
    # touch the target/source; exploit-agent and reporter have their own
    # headings and valid negative terminal states, so the gate is per-agent.
    if agent_type == "recon-agent":
        return (
            "environment facts" in summary
            and "host count" in summary
            and "endpoint count" in summary
        )
    if agent_type == "web-vuln-hunter":
        return (
            "environment facts" in summary
            and "confirmed findings" in summary
            and "suspected findings" in summary
        )
    if agent_type == "bypass-specialist":
        return (
            "environment facts" in summary
            and "bypass outcome" in summary
            and "transformation classes tested" in summary
            and "residual controls" in summary
        )
    if agent_type == "code-auditor":
        return (
            "environment facts" in summary
            and "confirmed" in summary
            and "suspected" in summary
        )
    if agent_type == "exploit-agent":
        # Must pass the gate-blocked / no-in-scope-target terminal state.
        return "impact" in summary and "roe gates" in summary
    if agent_type == "reporter":
        # Must pass a zero-findings report.
        return (
            "report path" in summary
            and "severity counts" in summary
            and "coverage gaps" in summary
        )
    return True


def _engagement_dir(payload: dict[str, Any]) -> Path | None:
    candidate = os.environ.get("PENTEST_ENGAGEMENT_DIR", "").strip()
    if not candidate:
        cwd = payload.get("cwd")
        if not isinstance(cwd, str) or not cwd.strip():
            return None
        try:
            project = Path(cwd).expanduser().resolve(strict=True)
            pointer = project / ".active_engagement"
            if not pointer.is_file() or pointer.stat().st_size > MAX_POINTER_BYTES:
                return None
            candidate = pointer.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            return None
    if not candidate or "\x00" in candidate:
        return None
    try:
        directory = Path(candidate).expanduser().resolve(strict=True)
    except OSError:
        return None
    return directory if directory.is_dir() else None


def _session_id(payload: dict[str, Any]) -> str:
    value = payload.get("session_id")
    return value.strip() if isinstance(value, str) else ""


def _owner_marker(engagement: Path) -> Path:
    return engagement / "state" / OWNER_MARKER_NAME


def _recorded_owner(engagement: Path) -> str | None:
    """Session id that owns this engagement, or None if unrecorded/unreadable."""
    marker = _owner_marker(engagement)
    try:
        if not marker.is_file() or marker.stat().st_size > MAX_OWNER_BYTES:
            return None
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    owner = data.get("session_id") if isinstance(data, dict) else None
    return owner.strip() if isinstance(owner, str) and owner.strip() else None


def _record_owner(engagement: Path, session_id: str) -> None:
    """Best-effort: mark this session as the engagement's completion-guard owner.

    Only the orchestrator dispatches the target subagents, so the session that
    produced a target SubagentStop is the run owner.  Idempotent: rewrites only
    when the recorded owner differs.  Never raises -- a failed write just leaves
    the guard fail-open (unscoped) for the next Stop.
    """
    if not session_id:
        return
    try:
        if _recorded_owner(engagement) == session_id:
            return
        marker = _owner_marker(engagement)
        marker.parent.mkdir(parents=True, exist_ok=True)
        temporary = marker.with_suffix(".json.tmp")
        temporary.write_text(json.dumps({"session_id": session_id}), encoding="utf-8")
        os.replace(temporary, marker)
    except OSError:
        pass


def _can_stop(engagement: Path) -> dict[str, Any] | None:
    state_path = engagement / "state" / "lead-state.json"
    try:
        if (
            not state_path.is_file()
            or state_path.stat().st_size <= 0
            or state_path.stat().st_size > MAX_STATE_BYTES
        ):
            return None
        sys.path.insert(0, str(ROOT / "lib"))
        run_path = engagement / "state" / "run.json"
        full_pentest = False
        if run_path.is_file() and 0 < run_path.stat().st_size <= MAX_RUN_BYTES:
            run = json.loads(run_path.read_text(encoding="utf-8"))
            full_pentest = (
                isinstance(run, dict) and run.get("current_phase") == "full-pentest"
            )
        if full_pentest:
            from campaign_coordinator import CampaignCoordinator  # type: ignore[import-not-found]

            outcome = CampaignCoordinator(engagement).outcome()
            completion = outcome.get("completion") or {}
            result = {
                "allowed": outcome.get("reporting_permitted") is True,
                "actionable": completion.get("actionable", 0),
            }
        else:
            from lead_store import LeadState  # type: ignore[import-not-found]

            result = LeadState(engagement).can_stop()
    except (ImportError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def main() -> int:
    payload = _read_input()
    if payload is None or payload.get("stop_hook_active") is True:
        return 0

    event = payload.get("hook_event_name")
    if event == "SubagentStop":
        agent_type = _agent_type(payload)
        if agent_type in TARGET_SUBAGENTS:
            # Only the orchestrator dispatches the target subagents, so this
            # SubagentStop's session identifies the run that owns the engagement.
            # Record it (best-effort) so the Stop gate can scope to that session.
            engagement = _engagement_dir(payload)
            if engagement is not None:
                _record_owner(engagement, _session_id(payload))
            if not _valid_subagent_summary(
                agent_type, payload.get("last_assistant_message")
            ):
                _block(
                    "Required pentest subagent summary fields are missing. "
                    "Return the exact summary headings documented for this subagent."
                )
        return 0

    if event != "Stop":
        return 0

    engagement = _engagement_dir(payload)
    if engagement is None:
        return 0
    # Scope the Stop gate to the run that owns the engagement.  A Stop from any
    # other session -- or before any owner is recorded -- passes through
    # untouched, so an unrelated session working in the repo during a live
    # engagement is never trapped.  This narrows WHICH Stops are inspected; the
    # guard stays fail-open on unknown ownership.
    owner = _recorded_owner(engagement)
    if owner is None or _session_id(payload) != owner:
        return 0
    decision = _can_stop(engagement)
    if decision is not None and decision.get("allowed") is False:
        if isinstance(decision.get("actionable"), int) and decision["actionable"] > 0:
            _block(
                "Actionable pentest work remains and loop budget permits another pass. "
                "Continue from the durable lead queue."
            )
        else:
            _block(
                "Campaign completion requirements remain unsatisfied. "
                "Continue through the deterministic coordinator."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
