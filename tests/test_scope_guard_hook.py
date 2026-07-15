#!/usr/bin/env python3
"""Regression tests for .claude/hooks/scope_guard.py extract().

extract() turns a Bash command into (network_seen, candidate_hosts). These
assert the target-extraction fixes: flag parsing is gated on an active network
tool, `-d` is tool-aware (domain vs POST data), shell redirects/subcommands are
not hosts, and `active_tool` does not leak across newline-separated statements.
Engagement-independent (scope in/out is decided elsewhere). Runs under pytest
(as test_*) and as a standalone script (exit != 0 on fail).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / ".claude" / "hooks"))
try:
    import scope_guard as sg  # noqa: E402
except ModuleNotFoundError:  # .claude/hooks absent from this checkout
    sg = None


def cands(command):
    return set(sg.extract(command)[1])


# (command, expected candidate hosts)
CASES = [
    # flag parsing must be gated on an active network tool
    ("wc -l /var/log/audit.jsonl", set()),
    ("tr -d '?&='", set()),
    ("sort -u out.txt", set()),
    ("grep -l pat file.txt", set()),
    # curl -d is POST data, not a host; only the in-scope URL is a candidate
    ("curl -s -d name=admin&pass=x https://app.example.com/login",
     {"https://app.example.com/login"}),
    ("curl -X POST -d a=b https://app.example.com/c", {"https://app.example.com/c"}),
    # subfinder/amass -d is a DOMAIN target (bare host candidate)
    ("subfinder -d target.com", {"target.com"}),
    ("amass enum -passive -d target.com", {"target.com"}),
    # -t is threads/templates, not a target
    ("nuclei -t cves/ -u https://app.example.com/", {"https://app.example.com/"}),
    ("httpx -t 50 -u https://app.example.com/", {"https://app.example.com/"}),
    # tool subcommands are not hosts (host:port bare candidate)
    ("openssl s_client -connect app.example.com:443", {"app.example.com:443"}),
    # output files / dump-header / redirects are NOT candidates
    ("curl -s -o body.b -D hdr.h https://app.example.com/", {"https://app.example.com/"}),
    ("nuclei -u https://app.example.com/ -o r.txt 2>e.log", {"https://app.example.com/"}),
    ("httpx -u https://app.example.com/ -json > out.json", {"https://app.example.com/"}),
    # active_tool must NOT leak across newline-separated statements (no r.txt host)
    ("nuclei -u https://app.example.com/ -o r.txt\necho done\ncat r.txt",
     {"https://app.example.com/"}),
    # out-of-scope host on a later line is still surfaced as a candidate
    ("echo hi\ncurl -s https://evil.other.com/x", {"https://evil.other.com/x"}),
    # url extraction backstop regardless of tool flags
    ("curl -s -d a=b https://evil.other.com/", {"https://evil.other.com/"}),
]


def test_scope_guard_extract():
    if sg is None:
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    mismatches = {cmd: {"want": sorted(want), "got": sorted(cands(cmd))}
                  for cmd, want in CASES if cands(cmd) != want}
    assert not mismatches, mismatches


if __name__ == "__main__":
    if sg is None:
        print("SKIP: scope_guard.py not present (.claude/hooks missing)")
        sys.exit(0)
    fail = 0
    print("scope_guard extract() self-test:")
    for cmd, want in CASES:
        got = cands(cmd)
        ok = got == want
        fail += 0 if ok else 1
        print(f"  {'ok  ' if ok else 'FAIL'} want={sorted(want)} got={sorted(got)} :: {cmd.splitlines()[0]}")
    print(f"\n{'PASS' if not fail else 'FAIL'}: {len(CASES) - fail}/{len(CASES)} cases")
    sys.exit(1 if fail else 0)
