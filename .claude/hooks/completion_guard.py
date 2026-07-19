#!/usr/bin/env python3
"""Deterministic completion guard for autonomous pentest loops.

The hook reasons only over the durable lead-state contract.  It never prints
lead content, paths, parser errors, or engagement data.  Invalid/missing state
is non-blocking so a damaged hook cannot trap Claude in an endless Stop loop.
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
TARGET_SUBAGENTS = {"recon-agent", "web-vuln-hunter"}


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
    if "environment facts" not in summary:
        return False
    if agent_type == "recon-agent":
        return "host count" in summary and "endpoint count" in summary
    if agent_type == "web-vuln-hunter":
        return "confirmed findings" in summary and "suspected findings" in summary
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
        if agent_type in TARGET_SUBAGENTS and not _valid_subagent_summary(
            agent_type, payload.get("last_assistant_message")
        ):
            _block(
                "Required pentest subagent summary fields are missing. "
                "Return the documented counts and Environment facts block."
            )
        return 0

    if event != "Stop":
        return 0

    engagement = _engagement_dir(payload)
    if engagement is None:
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
