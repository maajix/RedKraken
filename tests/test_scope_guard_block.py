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
    ("in-scope host allowed through reviewed runner",
     "./scripts/run_scoped_http.sh curl https://app.example.com/", GOOD_ENGAGEMENT, False),
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
    ("sudo-prefixed in-scope invocation allowed",
     "sudo ./scripts/run_scoped_http.sh curl https://app.example.com/", GOOD_ENGAGEMENT, False),
    ("timeout-prefixed in-scope invocation allowed",
     "timeout 300 ./scripts/run_scoped_http.sh nuclei -u https://app.example.com/", GOOD_ENGAGEMENT, False),
    ("env-prefixed out-of-scope invocation blocked", "env FOO=bar curl https://evil.other.org/x", GOOD_ENGAGEMENT, True),
    # A recognized network command whose only target is a shell variable is opaque
    # to static analysis -> fail closed (targetless block), prefix or not.
    ("variable-target network command blocked", 'curl "$URL"', GOOD_ENGAGEMENT, True),
    ("sudo variable-target network command blocked", 'sudo nmap "$URL"', GOOD_ENGAGEMENT, True),
    # `command -v <tool>` / `builtin -V <tool>` is shell name resolution, not an
    # executed network command -- it is the harness's own tool-preflight idiom and
    # must not be blocked for "no verifiable target". The exemption must not leak
    # past a separator, and `command <tool>` (real exec) stays fully gated.
    ("command -v preflight lookup of network tool allowed",
     'command -v nc >/dev/null 2>&1 || echo "MISSING:nc"', GOOD_ENGAGEMENT, False),
    ("builtin -V lookup of network tool allowed", "builtin -V curl", GOOD_ENGAGEMENT, False),
    ("command -v lookup then out-of-scope exec still blocked",
     "command -v curl >/dev/null && curl https://evil.other.org/", GOOD_ENGAGEMENT, True),
    ("command-prefixed out-of-scope real exec still blocked",
     "command curl https://evil.other.org/", GOOD_ENGAGEMENT, True),
    # Manual proxy wiring is not sufficient: NO_PROXY can override -x and curl
    # ignores uppercase HTTP_PROXY after an HTTPS->HTTP redirect. Only the reviewed
    # runner clears those bypasses and counts as mandatory transport.
    ("manual loopback proxy flag blocked",
     "curl --proxy http://127.0.0.1:18080 https://app.example.com/",
     GOOD_ENGAGEMENT, True),
    ("inline loopback proxy env blocked",
     "HTTPS_PROXY=http://127.0.0.1:18080 curl https://app.example.com/",
     GOOD_ENGAGEMENT, True),
    ("reviewed runner allows redirect-safe curl",
     "./scripts/run_scoped_http.sh curl -L https://app.example.com/",
     GOOD_ENGAGEMENT, False),
    ("documented browser wrapper through loopback proxy allowed",
     "./scripts/run_scoped_http.sh bash scripts/browser_capture.sh engagements/acme https://app.example.com owner "
     "--proxy http://127.0.0.1:18080",
     GOOD_ENGAGEMENT, False),
    ("documented schemathesis wrapper through loopback proxy allowed",
     "./scripts/run_scoped_http.sh bash scripts/run_schemathesis.sh "
     "engagements/acme ./openapi.yaml https://api.example.com",
     GOOD_ENGAGEMENT, False),
    ("out-of-scope target through reviewed runner blocked",
     "./scripts/run_scoped_http.sh curl https://evil.other.org/",
     GOOD_ENGAGEMENT, True),
    ("direct loopback target remains blocked",
     "curl http://127.0.0.1:18080/", GOOD_ENGAGEMENT, True),
    ("non-loopback proxy remains blocked",
     "curl --proxy http://proxy.other.net:8080 https://app.example.com/",
     GOOD_ENGAGEMENT, True),
    # URL-as-data: an out-of-scope URL that is only DATA to a local data-processing
    # command (grep/echo/awk/jq/sed over a recon list, including piped network
    # output) is not egress -> allowed. This lets hunters analyse passive-recon
    # output inline instead of forcing a script-file bypass...
    ("out-of-scope url as grep data allowed",
     "grep -F https://evil.other.org/ urls.txt", GOOD_ENGAGEMENT, False),
    ("out-of-scope urls as echo data allowed",
     "echo https://evil.other.org/a https://evil.other.org/b", GOOD_ENGAGEMENT, False),
    ("network output piped to grep of out-of-scope url allowed",
     "gau app.example.com | grep https://evil.other.org", GOOD_ENGAGEMENT, False),
    # ...while an egress-capable interpreter still fails closed: python3 is not a
    # data-processing command, so its inline os.system egress is scope-checked.
    ("python3 inline os.system out-of-scope egress still blocked",
     "python3 -c \"import os; os.system('curl https://evil.other.org/')\"",
     GOOD_ENGAGEMENT, True),
    # Info flags: a network tool invoked only to print version/help needs no
    # verifiable target -> allowed (same class as the `command -v` preflight). The
    # allowance is per whole-command: a real egress in a later statement is still
    # gated because not every network statement was info-only.
    ("curl --version info flag allowed", "curl --version", GOOD_ENGAGEMENT, False),
    ("wget --help info flag allowed", "wget --help", GOOD_ENGAGEMENT, False),
    ("nc -h help allowed", "nc -h", GOOD_ENGAGEMENT, False),
    ("info flag then out-of-scope egress still blocked",
     "curl --version; curl https://evil.other.org/", GOOD_ENGAGEMENT, True),
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


def test_list_file_flag_reads_and_scopes_targets():
    """subfinder -dL / amass -df batch targets from an inspectable file (the
    sanctioned alternative to one invocation per domain). Every listed target is
    scope-checked: an in-scope file is allowed, an out-of-scope one is blocked."""
    if not GUARD.is_file():
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    with tempfile.TemporaryDirectory() as directory:
        in_scope = Path(directory) / "in.txt"
        in_scope.write_text("app.example.com\napi.example.com\n", encoding="utf-8")
        oos = Path(directory) / "oos.txt"
        oos.write_text("evil.other.org\n", encoding="utf-8")
        failures = [
            msg for name, cmd, blk in [
                ("subfinder -dL in-scope file allowed", f"subfinder -dL {in_scope}", False),
                ("subfinder -dL out-of-scope file blocked", f"subfinder -dL {oos}", True),
                ("amass -df out-of-scope file blocked", f"amass enum -df {oos}", True),
            ]
            if (msg := check(name, cmd, GOOD_ENGAGEMENT, blk))
        ]
        assert not failures, "\n".join(failures)


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
