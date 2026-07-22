#!/usr/bin/env python3
"""Best-effort Bash target extraction backed by the strict scope parser."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from harness_config import ConfigError, load_engagement, resolve_engagement, scope_decision  # noqa: E402
from audit_event import append_event, redact, resolve_directory, sha256, utc_now  # noqa: E402


NETWORK_TOOLS = {
    "amass", "arjun", "curl", "dalfox", "dig", "dirb", "dirsearch", "dnsx",
    "feroxbuster", "ffuf", "gau", "gobuster", "gospider", "grpcurl", "hakrawler",
    "host", "httpx", "katana", "masscan", "mitmdump", "naabu",
    "nc", "ncat", "nikto", "nmap", "nuclei", "openssl", "paramspider", "ping",
    "schemathesis", "socat", "sqlmap", "sslscan", "sslyze", "ssh", "subfinder",
    "telnet", "testssl.sh", "tlsx", "wget", "whatweb", "waybackurls", "wfuzz",
    "wpscan", "wafw00f", "x8",
}
# HTTP(S)-egress tools that MUST run through the reviewed scoped-HTTP runner.
# The runner clears inherited proxy bypasses and sets every protocol-specific
# proxy variable; accepting a bare HTTP_PROXY or -x is unsafe because curl ignores
# uppercase HTTP_PROXY and NO_PROXY overrides even an explicit -x. DNS/passive/
# transport tools (subfinder,
# dnsx, amass, gau, waybackurls, nmap, openssl, nc, ...) are deliberately NOT
# here: they do not speak to the target over the HTTP proxy (passive archives,
# DNS, raw TLS/sockets), so requiring the proxy would wrongly break them.
PROXY_REQUIRED_TOOLS = {
    "curl", "wget", "httpx", "nuclei", "ffuf", "gobuster", "feroxbuster",
    "dirb", "dirsearch", "katana", "gospider", "hakrawler", "wfuzz", "wpscan",
    "dalfox", "sqlmap", "arjun", "schemathesis", "x8", "whatweb", "wafw00f",
}
# Bash allow entries that look security-related but must not be parsed as direct
# target tools. Keep this mapping narrow: tests reject new target-capable allow
# entries unless they are guarded above or carry an explicit reason here.
NETWORK_TOOL_EXEMPTIONS = {
    "jwt-tool": "offline token analysis; no target traffic",
    "playwright": "installer or launcher; target traffic uses scoped browser proxy",
    "zaproxy": "daemon launcher; target traffic uses scoped proxy workflow",
}
# Pure local data-processing commands: they never open a network connection, so a
# URL that appears in one of their statements is DATA (a pattern, a line being
# filtered, a field), not a destination. Statements led by these are not treated
# as egress, so out-of-scope URLs in passive-recon output (gau/waybackurls lists)
# can be analysed inline instead of forcing a script-file bypass. Anything not
# listed here stays egress-capable (fail closed): python3, bash, unknown tools.
DATA_PROCESSING = {
    "grep", "egrep", "fgrep", "rg", "echo", "printf", "cat", "tac", "head",
    "tail", "sort", "uniq", "awk", "gawk", "mawk", "nawk", "sed", "cut", "tr",
    "wc", "jq", "yq", "comm", "join", "paste", "column", "nl", "rev", "tee",
    "fold", "less", "more", "diff", "cmp", "base64", "xxd", "od", "strings",
    "dirname", "basename", "realpath", "readlink", "seq", "expand", "unexpand",
    "split", "csplit", "shuf",
}
# Unambiguous "the next token is a target host/url" flags. Short ambiguous flags
# (-d, -t) are handled tool-aware below because they collide with data/threads.
TARGET_FLAGS = {
    "-u", "--url", "--domain", "--target", "--connect", "-connect",
    "--host", "-host", "--hostname", "--base-url", "--endpoint",
}
# Tools where "-d <value>" means a target DOMAIN (else it's POST data, e.g. curl).
DOMAIN_D_TOOLS = {"subfinder", "amass"}
# Tool-specific list-file flags: "<flag> file" batches targets from an inspectable
# file (the sanctioned, MORE-checkable pattern) instead of one invocation each.
LIST_FILE_FLAGS = {"subfinder": {"-dL", "-dl"}, "amass": {"-df"}}
INPUT_FLAGS = {"-l", "-list", "--list", "--input-file", "-iL", "-K", "--config"}
# A network tool invoked purely to print version/help does not egress, so it needs
# no verifiable target -- same class as the `command -v <tool>` preflight idiom.
INFO_FLAGS = {"--version", "-version", "-V", "--help", "--usage", "-usage"}
# Tools where "-h <value>" is the target HOST rather than a help flag.
HOST_H_TOOLS = {"nikto"}
VALUE_FLAGS = {
    "-H", "--header", "-A", "--user-agent", "-X", "--request", "-w", "--wordlist",
    "-o", "--output", "-D", "--dump-header", "-c", "--concurrency", "-rl",
    "--rate-limit", "--threads", "-t", "-p", "--ports", "--proxy", "-x",
    "--data", "--data-raw", "--cookie", "-b",
}
URL_RE = re.compile(r"https?://[^\s\"'`<>]+", re.IGNORECASE)
GENERIC_NETWORK_RE = re.compile(r"\b(requests|urllib|urlopen|httpx|aiohttp|socket|websocket|grpc)\b")
# A bare token is only a candidate host if it is hostname/IPv4[:port]-shaped.
# Excludes shell redirects (2>err.log), key=val data, and tool subcommands
# (openssl "s_client", amass "enum") that would otherwise be scope-checked.
HOST_TOKEN_RE = re.compile(r"[A-Za-z0-9._\-]+(?::\d+)?$")
# Transparent prefixes run the FOLLOWING token as the real command (sudo curl …,
# timeout 300 nuclei …, xargs ffuf …). Seeing one keeps the command position open
# and flips the statement to fail-closed "loose" mode, so a network tool anywhere
# later is still caught even when the prefix's own args confuse position tracking.
PREFIX_COMMANDS = {
    "sudo", "doas", "env", "nohup", "setsid", "stdbuf", "nice", "ionice",
    "time", "timeout", "watch", "xargs", "command", "builtin",
    "proxychains", "proxychains4",
}
SCOPED_HTTP_RUNNER = (ROOT / "scripts" / "run_scoped_http.sh").resolve()
# Shell block-openers introduce a fresh simple command (`for h in …; do curl …`,
# `if …; then wget …`). They must reset the command position so a network tool
# right after them is still seen as the command -- otherwise a single-line loop
# hides egress from the guard and fails OPEN. Block-closers (done/fi/esac) do not
# precede a command and need no handling.
BLOCK_KEYWORDS = {"do", "then", "else"}
ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
PROXY_FLAGS = {"--proxy", "-x"}
PROXY_ENV_NAMES = {
    "PENTEST_PROXY",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
}


def decision(reason: str, command: str = "") -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"SCOPE BLOCK: {reason}"[:500],
        }
    }
    print(json.dumps(payload, separators=(",", ":")))
    # A denied command never executes, so the PostToolUse audit hook never fires
    # -- this is the only chance to record the block. Best-effort and fully
    # isolated: an audit failure must never suppress the deny emitted above.
    try:
        directory = resolve_directory()
        if directory is not None:
            append_event(directory, {
                "schema_version": 1,
                "ts": utc_now(),
                "event": "scope-block",
                "tool": "Bash",
                "reason": reason[:500],
                "command": redact(command),
                "command_sha256": sha256(command) if command else "",
            })
    except Exception:  # noqa: BLE001 - logging must not affect the block decision
        pass


def clean_candidate(value: str) -> str:
    return value.strip().strip("\"'").rstrip(",;)")


def loopback_proxy_url(value: str) -> str | None:
    """Return a normalized HTTP(S) proxy URL only when it is loopback."""
    candidate = clean_candidate(value)
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not host:
        return None
    if host.rstrip(".").casefold() == "localhost":
        return candidate
    try:
        return candidate if ipaddress.ip_address(host).is_loopback else None
    except ValueError:
        return None


def loopback_proxy_values(token_lists: list[list[str]]) -> Counter[str]:
    """Count loopback URLs used specifically as proxy transport values."""
    proxies: Counter[str] = Counter()
    for tokens in token_lists:
        for index, token in enumerate(tokens):
            value = ""
            if token in PROXY_FLAGS and index + 1 < len(tokens):
                value = tokens[index + 1]
            elif any(token.startswith(f"{flag}=") for flag in PROXY_FLAGS):
                value = token.split("=", 1)[1]
            else:
                name, separator, assigned = token.partition("=")
                if separator and name in PROXY_ENV_NAMES:
                    value = assigned
            proxy = loopback_proxy_url(value) if value else None
            if proxy:
                proxies[proxy] += 1
    return proxies


def is_scoped_http_runner(token: str) -> bool:
    """True only for this checkout's reviewed runner, never a same-name script."""
    candidate = Path(token).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve() == SCOPED_HTTP_RUNNER


def targets_from_file(value: str) -> list[str]:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    try:
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            raise ConfigError(f"target input is missing, not a file, or too large: {value}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ConfigError(f"cannot inspect target input {value}: {exc}") from exc
    targets: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lstrip("-").casefold() == "next" or re.match(
            r"(?i)(?:--)?(?:proxy|preproxy|noproxy|socks\w*)(?:\s*=|\s+)", stripped
        ):
            raise ConfigError(f"proxy/bypass directives are not allowed in target input: {value}")
        config_match = re.match(r"(?i)url\s*=\s*(.+)", stripped)
        if config_match:
            stripped = config_match.group(1).strip().strip("\"'")
        else:
            stripped = stripped.split()[0]
        if stripped:
            targets.append(clean_candidate(stripped))
    return targets


def split_separators(tokens: list[str]) -> list[str]:
    """Break a `;` command separator that shlex left fused to an adjacent token.

    `shlex.split("for h in $(cat s); do curl \"$h\"; done")` yields `s);` and
    `$h;` as single tokens, so `_scan_tokens`'s statement-boundary reset (which
    matches a standalone `;`) never fires and `curl` never reaches command
    position -> the loop fails OPEN. `;` is unambiguously a shell command
    separator; a `;` inside quoted data (rare, e.g. POST bodies) only yields a
    harmless extra command-position reset, which stays fail-closed.
    """
    out: list[str] = []
    for token in tokens:
        if ";" not in token:
            out.append(token)
            continue
        out.extend(part for part in re.split(r"(;)", token) if part)
    return out


def _scan_tokens(
    tokens: list[str], command: str
) -> tuple[bool, list[str], list[str], int, int, bool]:
    host_candidates: list[str] = []
    url_candidates: list[str] = []
    network_cmd = False    # a network tool actually invoked in command position
    stmt_summaries: list[tuple[bool, bool]] = []  # (network, info-only) per statement
    needs_proxy = False    # at least one HTTP egress statement lacks the reviewed runner
    active_tool = ""
    cmd_pos = True         # the next ordinary word is a command being executed
    loose = False          # a transparent prefix put us in fail-closed over-include
    skip_value = False
    target_value = False
    input_value = False
    command_prefix = False  # inside a `command`/`builtin` invocation
    lookup = False          # `command -v`/`-V`: shell name resolution, not exec
    stmt_egress = True      # statement egresses unless its command is pure data-processing
    stmt_network = False    # a network tool was the command of this statement
    stmt_info = False       # that network tool was invoked info-only (--version/-h/…)
    stmt_proxy_required = False
    stmt_scoped_runner = False
    stmt_tokens: list[str] = []

    def flush() -> None:
        nonlocal needs_proxy
        # A statement contributes URL candidates only when it can actually egress.
        # Pure data-processing statements (grep/echo/awk/jq over a URL list) carry
        # URLs as DATA, not destinations, so their URLs are not scope-checked.
        if stmt_egress:
            for match in URL_RE.findall(" ".join(stmt_tokens)):
                cleaned = clean_candidate(match)
                if cleaned:
                    url_candidates.append(cleaned)
        stmt_summaries.append((stmt_network, stmt_info))
        if stmt_network and not stmt_info and stmt_proxy_required and not stmt_scoped_runner:
            needs_proxy = True

    for token in tokens:
        if token in {"|", "||", "&&", ";", "&"}:
            flush()
            active_tool = ""
            cmd_pos = True
            loose = False
            skip_value = target_value = input_value = False
            command_prefix = lookup = False
            stmt_egress = True
            stmt_network = False
            stmt_info = False
            stmt_proxy_required = False
            stmt_scoped_runner = False
            stmt_tokens = []
            continue
        stmt_tokens.append(token)
        if token in {">", ">>", "<", "2>", "2>>", "1>", "&>", "&>>"}:
            skip_value = True  # the following token is a redirect target file
            continue
        if target_value:
            host_candidates.append(clean_candidate(token))
            target_value = False
            cmd_pos = False
            continue
        if input_value:
            host_candidates.extend(targets_from_file(token))
            input_value = False
            cmd_pos = False
            continue
        if skip_value:
            skip_value = False
            continue
        basename = os.path.basename(token)
        # Command-position gate: a token only marks the statement as a network
        # command when it is the command actually being executed. A tool NAME used
        # as a bare argument (`echo nmap`, `grep -r ffuf`, `for f in … ffuf …`)
        # must not trip the guard. Transparent prefixes (sudo/env/xargs/timeout/…)
        # run the following token, so they hold the command position open AND set
        # `loose`, keeping a network tool later in the statement fail-closed.
        if cmd_pos:
            if command_prefix and token in {"-v", "-V"}:
                # `command -v nc` / `builtin -V curl`: shell name resolution, not
                # an executed network command. Inspecting a tool's presence must
                # not require a target -- it is the harness's own preflight idiom.
                lookup = True
                continue
            if token.startswith("-") or ASSIGN_RE.match(token):
                continue  # a prefix's own flag or NAME=value; stay at command pos
            if basename in {"command", "builtin"}:
                loose = True
                command_prefix = True
                continue
            if is_scoped_http_runner(token):
                stmt_scoped_runner = True
                loose = True
                continue
            if basename == SCOPED_HTTP_RUNNER.name:
                # A same-name helper outside this checkout is an untrusted prefix:
                # inspect the following tool, but never grant proxy transport.
                loose = True
                continue
            if basename in PREFIX_COMMANDS:
                loose = True
                continue
            if basename in BLOCK_KEYWORDS:
                # A block-opener precedes a fresh command; keep command position
                # open so the following network tool is still detected.
                continue
            cmd_pos = False
            if lookup:
                continue  # a resolved-but-unexecuted name carries no target
            if basename in NETWORK_TOOLS:
                network_cmd = True
                stmt_network = True
                active_tool = basename
                stmt_proxy_required = basename in PROXY_REQUIRED_TOOLS
                continue
            if basename in {"python", "python3"} and GENERIC_NETWORK_RE.search(command):
                network_cmd = True
                stmt_network = True
                active_tool = basename
                continue
            if not loose and basename in DATA_PROCESSING:
                stmt_egress = False  # pure data-processing statement: URLs are data
            # else: unknown command -> stmt_egress stays True (fail closed)
        elif loose and is_scoped_http_runner(token):
            stmt_scoped_runner = True
            continue
        elif loose and basename in NETWORK_TOOLS:
            network_cmd = True
            stmt_network = True
            active_tool = basename
            stmt_proxy_required = basename in PROXY_REQUIRED_TOOLS
            continue
        # Only interpret target/input/value flags while a network tool is the
        # active command; otherwise "-l"/"-d"/"-t" on plain commands (wc -l,
        # tr -d, sort -t) would be misread as targets or trigger file reads.
        if active_tool:
            if token in INFO_FLAGS:
                stmt_info = True  # version/help: invoked but not egressing
                continue
            if token in {"-h", "-help"}:
                if active_tool in HOST_H_TOOLS:
                    target_value = True  # nikto -h <host>
                else:
                    stmt_info = True     # help text, not a target
                continue
            if token in TARGET_FLAGS:
                target_value = True
                continue
            if token == "-d":
                if active_tool in DOMAIN_D_TOOLS:
                    target_value = True
                else:  # curl/sqlmap/wpscan: -d is request/POST data, not a host
                    skip_value = True
                continue
            if token in LIST_FILE_FLAGS.get(active_tool, frozenset()):
                input_value = True  # subfinder -dL / amass -df: inspectable target file
                continue
            if token in INPUT_FLAGS:
                input_value = True
                continue
            if token in VALUE_FLAGS:
                skip_value = True
                continue
        if active_tool and not token.startswith("-"):
            cand = clean_candidate(token)
            # Only a host-like bare token is a target (dotted domain/IPv4 with
            # optional :port, or bracketed IPv6). Skips tool subcommands like
            # openssl "s_client"/amass "enum", key=val data, and shell redirects
            # such as 2>err.log; real URLs are caught by URL_RE anyway.
            host_like = cand.startswith("[") or (
                "." in cand and bool(HOST_TOKEN_RE.fullmatch(cand))
            )
            if host_like and cand.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"} and not Path(token).is_file():
                host_candidates.append(cand)
                active_tool = ""
    flush()
    network_stmt_count = sum(1 for net, _ in stmt_summaries if net)
    info_stmt_count = sum(1 for net, info in stmt_summaries if net and info)
    return network_cmd, host_candidates, url_candidates, network_stmt_count, info_stmt_count, needs_proxy


def extract(command: str) -> tuple[bool, list[str], bool, bool]:
    # Scan each newline-separated statement with fresh state so a network tool
    # on one line cannot leak `active_tool` onto the next (which would misread a
    # later dotted filename like `cat out.txt` as a host). If a quoted argument
    # spans lines, per-line shlex fails -> fall back to one whole-command scan.
    lines = command.splitlines() or [command]
    token_lists: list[list[str]] = []
    try:
        for line in lines:
            if line.strip():
                token_lists.append(split_separators(shlex.split(line, posix=True)))
    except ValueError:
        try:
            token_lists = [split_separators(shlex.split(command, posix=True))]
        except ValueError as exc:
            if any(re.search(rf"\b{re.escape(tool)}\b", command) for tool in NETWORK_TOOLS):
                raise ConfigError(f"cannot parse network command: {exc}") from exc
            urls = [clean_candidate(value) for value in URL_RE.findall(command)]
            return False, list(dict.fromkeys(v for v in urls if v)), False, False

    proxy_values = loopback_proxy_values(token_lists)
    network_seen = False
    host_candidates: list[str] = []
    url_candidates: list[str] = []
    network_stmt_count = 0
    info_stmt_count = 0
    needs_proxy = False
    for tokens in token_lists:
        seen, hosts, urls, net_ct, info_ct, statement_needs_proxy = _scan_tokens(tokens, command)
        network_seen = network_seen or seen
        host_candidates.extend(hosts)
        url_candidates.extend(urls)
        network_stmt_count += net_ct
        info_stmt_count += info_ct
        needs_proxy = needs_proxy or statement_needs_proxy

    # A recognized loopback proxy is transport, not a destination: subtract one
    # URL occurrence per counted proxy use so the real target stays visible.
    kept_urls: list[str] = []
    for value in url_candidates:
        if proxy_values.get(value, 0) > 0:
            proxy_values[value] -= 1
        else:
            kept_urls.append(value)

    candidates = list(dict.fromkeys(value for value in (host_candidates + kept_urls) if value))
    # A command is "targetless" only if every network statement was info-only; a
    # single real egress with no verifiable target still fails closed.
    all_network_info_only = network_stmt_count > 0 and info_stmt_count == network_stmt_count
    return network_seen, candidates, all_network_info_only, needs_proxy


def main() -> int:
    try:
        hook = json.load(sys.stdin)
        command = str((hook.get("tool_input") or {}).get("command") or "")
    except (json.JSONDecodeError, AttributeError):
        decision("unparseable hook input")
        return 0
    if not command:
        return 0
    try:
        network_seen, candidates, info_only, needs_proxy = extract(command)
        if network_seen and not candidates and not info_only:
            raise ConfigError(
                "network command has no statically verifiable target: a shell "
                "variable, command substitution, or loop hides the destination "
                "from scope enforcement. Pass literal in-scope targets or an "
                "inspectable target file (e.g. httpx -l hosts.txt, nuclei -l "
                "hosts.txt, subfinder -dL domains.txt)."
            )
        if not candidates:
            return 0
        yaml_path = resolve_engagement(None, root=ROOT)
        config = load_engagement(yaml_path)
        for candidate in candidates:
            allowed, host, reason = scope_decision(config, candidate)
            if not allowed:
                raise ConfigError(f"target {host!r} denied: {reason}")
        # In scope, but an HTTP-egress tool would reach the target OFF-PROXY: the
        # rate policy and required headers (X-Bug-Bounty) live in the proxy, so a
        # direct call violates RoE even in scope. Fail closed.
        if needs_proxy:
            raise ConfigError(
                "in-scope HTTP-egress tool would bypass the scope proxy: run it as "
                "`./scripts/run_scoped_http.sh <tool> ...` so redirects, inherited "
                "NO_PROXY, required headers, and the aggregate rate limit stay inside "
                "the enforcement boundary."
            )
    except ConfigError as exc:
        decision(str(exc), command)
    except Exception as exc:  # noqa: BLE001 - a scope guard must fail closed on ANY error
        decision(f"scope guard internal error ({type(exc).__name__}): {exc}", command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
