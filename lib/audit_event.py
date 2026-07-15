#!/usr/bin/env python3
"""Write tamper-evident-friendly structured audit events without secret values."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s'\"]+"),
    re.compile(r"(?i)((?:x-api-key|api[_-]?key|token|password|secret|cookie)\s*[:=]\s*)[^\s'\"]+"),
    re.compile(r"(?i)(--(?:password|token|api-key|header)\s+)([^\s]+)"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def redact(value: str) -> str:
    result = value
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}<redacted>", result)
    return result


def resolve_directory(explicit: str | None = None) -> Path | None:
    value = explicit or os.environ.get("PENTEST_ENGAGEMENT_DIR", "")
    if not value:
        try:
            value = (ROOT / ".active_engagement").read_text(encoding="utf-8").strip()
        except OSError:
            return None
    return Path(value).expanduser().resolve()


def append_event(directory: Path, event: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "audit.jsonl"
    payload = json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n"
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.chmod(path, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def event_from_hook(data: dict[str, Any]) -> dict[str, Any]:
    tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
    command = str(tool_input.get("command", ""))
    response = data.get("tool_response")
    response_text = json.dumps(response, sort_keys=True, default=str) if response is not None else ""
    error = str(data.get("error", ""))
    event: dict[str, Any] = {
        "schema_version": 1,
        "ts": utc_now(),
        "event": data.get("hook_event_name", "tool"),
        "session_id": data.get("session_id", ""),
        "agent_id": data.get("agent_id", ""),
        "tool_use_id": data.get("tool_use_id", ""),
        "tool": data.get("tool_name", ""),
        "command": redact(command),
        "command_sha256": sha256(command),
        "duration_ms": data.get("duration_ms"),
    }
    if response_text:
        event["response_sha256"] = sha256(response_text)
    if error:
        event["error"] = redact(error)[:1000]
        event["error_sha256"] = sha256(error)
    return event


def hook_main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    directory = resolve_directory()
    if directory is None:
        return 0
    try:
        append_event(directory, event_from_hook(data))
    except OSError as exc:
        print(f"audit hook failed: {exc}", file=sys.stderr)
    return 0


def manual_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", nargs="?", default="?")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    parser.add_argument("--engagement", dest="engagement")
    args = parser.parse_args(argv[1:])
    directory = resolve_directory(args.engagement)
    if directory is None:
        print("audit: no engagement loaded; not logging", file=sys.stderr)
        return 0
    command = " ".join(args.command)
    event = {
        "schema_version": 1,
        "ts": utc_now(),
        "event": "manual-command",
        "phase": args.phase,
        "command": redact(command),
        "command_sha256": sha256(command),
    }
    try:
        append_event(directory, event)
    except OSError as exc:
        print(f"audit: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(hook_main() if os.environ.get("HARNESS_AUDIT_HOOK") == "1" else manual_main(sys.argv))
