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


def needs_proxy(command):
    return sg.extract(command)[3]


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
    # A recognized loopback proxy is transport, not the request target. The real
    # destination must remain visible to scope enforcement.
    ("curl --proxy http://127.0.0.1:18080 https://app.example.com/",
     {"https://app.example.com/"}),
    ("curl -x http://localhost:18080 https://app.example.com/",
     {"https://app.example.com/"}),
    ("HTTPS_PROXY=http://127.0.0.1:18080 curl https://app.example.com/",
     {"https://app.example.com/"}),
    ("env PENTEST_PROXY=http://[::1]:18080 curl https://app.example.com/",
     {"https://app.example.com/"}),
    # The exemption is role- and destination-specific: direct loopback targets
    # and non-loopback proxies are still scope candidates.
    ("curl http://127.0.0.1:18080/", {"http://127.0.0.1:18080/"}),
    ("curl --proxy http://proxy.other.net:8080 https://app.example.com/",
     {"http://proxy.other.net:8080", "https://app.example.com/"}),
    # URL-as-data: a URL inside a pure data-processing statement (grep/echo/sed/
    # jq over a recon list) is DATA being filtered, not a destination -> no host.
    ("grep -F https://evil.other.org/ urls.txt", set()),
    ("echo https://evil.other.org/a https://evil.other.org/b", set()),
    # network output piped to a data filter: only the network statement's host is
    # a candidate; the filter's URL argument is data.
    ("gau app.example.com | grep https://evil.other.org", {"app.example.com"}),
    # ...but an egress-capable interpreter still contributes its inline URL, so a
    # `python3 -c os.system('curl <oos>')` egress stays visible to scope.
    ("python3 -c \"import os; os.system('curl https://evil.other.org/')\"",
     {"https://evil.other.org/"}),
    # info flags (--version/--help/-V, and -h except host-taking tools like nikto)
    # print text without egress -> no target candidate.
    ("curl --version", set()),
    ("nc -h", set()),
    ("nikto -h app.example.com", {"app.example.com"}),
]


def test_scope_guard_extract():
    if sg is None:
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    mismatches = {cmd: {"want": sorted(want), "got": sorted(cands(cmd))}
                  for cmd, want in CASES if cands(cmd) != want}
    assert not mismatches, mismatches


# Egress hidden in a single-line shell loop must NOT fail open. shlex fuses the
# `;` separators (`subs.txt);`, `$h;`) so the statement never resets to command
# position; without the split+block-keyword handling, `curl` goes unseen and the
# command is silently ALLOWED. Each must surface as real egress (network=True,
# not info-only) with no statically verifiable target -> the hook denies.
LOOP_FAILOPEN_CASES = [
    'for h in $(cat subs.txt); do curl -s "$h"; done',
    'for h in $(cat subs.txt);do curl -s "$h";done',
    'while read h; do curl "$h"; done < subs.txt',
]


def test_loop_egress_is_not_fail_open():
    if sg is None:
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    for cmd in LOOP_FAILOPEN_CASES:
        network_seen, candidates, info_only, _needs_proxy = sg.extract(cmd)
        assert network_seen and not info_only and not candidates, \
            (cmd, network_seen, candidates, info_only)


# HTTP(S) egress must use the reviewed runner. A bare proxy env or -x is not a
# sufficient guarantee: curl ignores uppercase HTTP_PROXY on an HTTPS->HTTP
# redirect, and inherited NO_PROXY overrides even -x. The runner clears those
# bypasses while keeping the underlying tool and targets visible to this parser.
PROXY_REQUIRED_CASES = [
    # bare HTTP-egress tool + in-scope target, no proxy -> MUST flag
    ("curl -s https://app.example.com/login", True),
    ("wget https://app.example.com/x", True),
    ("nuclei -u https://app.example.com/", True),
    ("ffuf -w w.txt -u https://app.example.com/FUZZ", True),
    ("whatweb app.example.com", True),
    # partial/manual proxy wiring is still bypassable -> MUST flag
    ("HTTPS_PROXY=http://127.0.0.1:18080 curl -L https://app.example.com/login", True),
    ("HTTP_PROXY=http://127.0.0.1:18080 HTTPS_PROXY=http://127.0.0.1:18080 curl https://app.example.com/", True),
    ("curl -x http://127.0.0.1:18080 https://app.example.com/", True),
    ("HTTPS_PROXY=http://127.0.0.1:18080 nuclei -u https://app.example.com/", True),
    # reviewed runner on the same shell statement -> safe
    ("./scripts/run_scoped_http.sh curl -L https://app.example.com/login", False),
    ("./scripts/run_scoped_http.sh nuclei -u https://app.example.com/", False),
    ("state/scratch/run_scoped_http.sh curl https://app.example.com/", True),
    # proxy evidence elsewhere in a compound command cannot bless a later curl
    ("./scripts/run_scoped_http.sh true; curl https://app.example.com/", True),
    ("echo HTTPS_PROXY=http://127.0.0.1:18080; curl https://app.example.com/", True),
    # info-only (no egress) -> must NOT flag even without a proxy
    ("curl --version", False),
    ("curl --help", False),
    # DNS / passive / transport tools do NOT use the HTTP proxy -> must NOT flag
    ("subfinder -d target.com", False),
    ("amass enum -passive -d target.com", False),
    ("dnsx target.com", False),
    ("gau app.example.com", False),
    ("waybackurls app.example.com", False),
    ("openssl s_client -connect app.example.com:443", False),
    ("nmap -p 443 app.example.com", False),
    # pure data-processing mentioning a tool name is not egress -> must NOT flag
    ("echo curl https://app.example.com/", False),
    ("grep -F https://app.example.com/ urls.txt", False),
]


def test_proxy_required_for_http_egress():
    if sg is None:
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    mismatches = {cmd: {"want": want, "got": needs_proxy(cmd)}
                  for cmd, want in PROXY_REQUIRED_CASES if needs_proxy(cmd) != want}
    assert not mismatches, mismatches


def test_curl_config_rejects_proxy_bypass_directives():
    if sg is None:
        import pytest
        pytest.skip("scope_guard.py not present (.claude/hooks missing)")
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "targets.curlcfg"
        config.write_text(
            'url = "https://app.example.com/"\nnext\nurl = "https://app.example.com/"\n',
            encoding="utf-8",
        )
        try:
            sg.extract(f"./scripts/run_scoped_http.sh curl -K {config}")
        except sg.ConfigError:
            return
        raise AssertionError("curl config bypass directive was accepted")


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
    checks = (
        ("single-line loop egress", test_loop_egress_is_not_fail_open),
        ("mandatory scoped runner", test_proxy_required_for_http_egress),
        ("curl config bypass rejection", test_curl_config_rejects_proxy_bypass_directives),
    )
    for name, check in checks:
        try:
            check()
            print(f"  ok   {name}")
        except Exception as exc:  # noqa: BLE001 - standalone test reports all failures
            fail += 1
            print(f"  FAIL {name}: {exc}")
    total = len(CASES) + len(checks)
    print(f"\n{'PASS' if not fail else 'FAIL'}: {total - fail}/{total} cases")
    sys.exit(1 if fail else 0)
