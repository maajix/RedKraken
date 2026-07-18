#!/usr/bin/env python3
"""End-to-end deny-path tests for .claude/hooks/scope_guard.py main().

test_scope_guard_hook.py covers extract() (parsing) only. This file covers the
branches that actually gate traffic: the guard must BLOCK out-of-scope /
targetless / malformed-config commands, must ALLOW in-scope and non-network
commands, and every block must leave a `scope-block` audit event (a denied
command never executes, so PostToolUse never logs it -- the PreToolUse guard is
the only writer). Runs the real script as a subprocess against an isolated
engagement dir so nothing here touches the operator's live .active_engagement.

Runs under pytest (as test_*) and as a standalone script (exit != 0 on fail).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / ".claude" / "hooks" / "scope_guard.py"
TOKEN_PLACEHOLDER = "<SYNTHETIC_TOKEN_NOT_A_CREDENTIAL>"

# targets is a wildcard so out_of_scope has something to override; secret.* is
# carved back out to exercise the deny-before-allow ordering.
GOOD_ENGAGEMENT = 'targets:\n  - "*.example.com"\nout_of_scope:\n  - "secret.example.com"\n'
MALFORMED_ENGAGEMENT = "targets: not-a-list\n"


def run_guard(command: str, engagement_yaml: str = GOOD_ENGAGEMENT) -> tuple[str, list[dict]]:
    """Run the guard on one command in a throwaway engagement; return (stdout, audit_events)."""
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "engagement.yaml").write_text(engagement_yaml, encoding="utf-8")
        env = {**os.environ, "PENTEST_ENGAGEMENT_DIR": directory, "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, str(GUARD)],
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
            text=True, capture_output=True, env=env, timeout=30,
        )
        audit = Path(directory) / "audit.jsonl"
        events = [json.loads(line) for line in audit.read_text().splitlines()] if audit.exists() else []
        return proc.stdout.strip(), events


def is_deny(stdout: str) -> bool:
    return '"permissionDecision":"deny"' in stdout


def blocked_events(events: list[dict]) -> list[dict]:
    return [event for event in events if event.get("event") == "scope-block"]


# (name, command, engagement, expect_block)
CASES = [
    ("in-scope host allowed", "curl https://app.example.com/", GOOD_ENGAGEMENT, False),
    ("out-of-scope host blocked (not in targets)", "curl https://evil.other.org/x", GOOD_ENGAGEMENT, True),
    ("explicit out_of_scope blocked (deny before allow)", "curl https://secret.example.com/", GOOD_ENGAGEMENT, True),
    ("network tool with no verifiable target blocked", "curl", GOOD_ENGAGEMENT, True),
    ("malformed engagement fails closed", "curl https://app.example.com/", MALFORMED_ENGAGEMENT, True),
    ("non-network command allowed (not scanned)", "wc -l notes.txt", GOOD_ENGAGEMENT, False),
    # Command-position awareness: a NETWORK_TOOLS name used as a bare ARGUMENT (not
    # the executed command) must NOT trip the guard. These were false positives
    # before the cmd_pos rewrite of _scan_tokens.
    ("tool name as echo argument allowed", "echo nmap is a tool", GOOD_ENGAGEMENT, False),
    ("tool name as grep pattern allowed", "grep -r ffuf playbooks/", GOOD_ENGAGEMENT, False),
    ("tool names as for-loop list words allowed", "for t in nmap ffuf sqlmap; do echo $t; done", GOOD_ENGAGEMENT, False),
    # ...but a transparent prefix (sudo/timeout/env/...) still runs the following
    # command, so a real in-scope invocation is allowed and the fail-closed target
    # rules still apply to it.
    ("sudo-prefixed in-scope invocation allowed", "sudo curl https://app.example.com/", GOOD_ENGAGEMENT, False),
    ("timeout-prefixed in-scope invocation allowed", "timeout 300 nuclei -u https://app.example.com/", GOOD_ENGAGEMENT, False),
    ("env-prefixed out-of-scope invocation blocked", "env FOO=bar curl https://evil.other.org/x", GOOD_ENGAGEMENT, True),
    # A recognized network command whose only target is a shell variable is opaque
    # to static analysis -> fail closed (targetless block), prefix or not.
    ("variable-target network command blocked", 'curl "$URL"', GOOD_ENGAGEMENT, True),
    ("sudo variable-target network command blocked", 'sudo nmap "$URL"', GOOD_ENGAGEMENT, True),
]


def check(name: str, command: str, engagement: str, expect_block: bool) -> str | None:
    stdout, events = run_guard(command, engagement)
    blocks = blocked_events(events)
    if expect_block:
        if not is_deny(stdout):
            return f"{name}: expected deny on stdout, got {stdout!r}"
        if not blocks:
            return f"{name}: expected a scope-block audit event, got {events!r}"
        if not blocks[0].get("command_sha256"):
            return f"{name}: scope-block event missing command_sha256"
    else:
        if stdout:
            return f"{name}: expected allow (empty stdout), got {stdout!r}"
        if blocks:
            return f"{name}: expected no scope-block audit event, got {blocks!r}"
    return None


def test_scope_guard_blocks_and_logs():
    if not GUARD.is_file():
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    failures = [msg for name, cmd, eng, blk in CASES if (msg := check(name, cmd, eng, blk))]
    assert not failures, "\n".join(failures)


def test_secret_redacted_in_block_event():
    if not GUARD.is_file():
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    command = f'curl -H "Authorization: Bearer {TOKEN_PLACEHOLDER}" https://evil.other.org/'
    stdout, events = run_guard(command)
    blocks = blocked_events(events)
    assert is_deny(stdout), stdout
    assert blocks, events
    logged = json.dumps(blocks[0])
    assert TOKEN_PLACEHOLDER not in logged, f"synthetic token leaked into audit: {logged}"
    assert "<redacted>" in blocks[0]["command"], blocks[0]["command"]


if __name__ == "__main__":
    if not GUARD.is_file():
        print("SKIP: scope_guard.py not present (.claude/hooks missing)")
        sys.exit(0)
    fail = 0
    print("scope_guard block-path self-test:")
    for name, cmd, eng, blk in CASES:
        msg = check(name, cmd, eng, blk)
        fail += 1 if msg else 0
        print(f"  {'FAIL' if msg else 'ok  '} {name}" + (f"\n       {msg}" if msg else ""))
    # secret-redaction case
    try:
        out, evs = run_guard(
            f'curl -H "Authorization: Bearer {TOKEN_PLACEHOLDER}" https://evil.other.org/'
        )
        blk = blocked_events(evs)
        red_ok = is_deny(out) and blk and TOKEN_PLACEHOLDER not in json.dumps(blk[0]) and "<redacted>" in blk[0]["command"]
    except Exception as exc:  # noqa: BLE001
        red_ok = False
        print(f"       redaction case raised: {exc}")
    fail += 0 if red_ok else 1
    print(f"  {'ok  ' if red_ok else 'FAIL'} secret redacted in block event")
    print(f"\n{'PASS' if not fail else 'FAIL'}: {len(CASES) + 1 - fail}/{len(CASES) + 1} cases")
    sys.exit(1 if fail else 0)
