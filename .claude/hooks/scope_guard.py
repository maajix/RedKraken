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
# Bash allow entries that look security-related but must not be parsed as direct
# target tools. Keep this mapping narrow: tests reject new target-capable allow
# entries unless they are guarded above or carry an explicit reason here.
NETWORK_TOOL_EXEMPTIONS = {
    "jwt-tool": "offline token analysis; no target traffic",
    "playwright": "installer or launcher; target traffic uses scoped browser proxy",
    "zaproxy": "daemon launcher; target traffic uses scoped proxy workflow",
}
# Unambiguous "the next token is a target host/url" flags. Short ambiguous flags
# (-d, -t) are handled tool-aware below because they collide with data/threads.
TARGET_FLAGS = {
    "-u", "--url", "--domain", "--target", "--connect", "-connect",
    "--host", "-host", "--hostname", "--base-url", "--endpoint",
}
# Tools where "-d <value>" means a target DOMAIN (else it's POST data, e.g. curl).
DOMAIN_D_TOOLS = {"subfinder", "amass"}
INPUT_FLAGS = {"-l", "-list", "--list", "--input-file", "-iL", "-K", "--config"}
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
        config_match = re.match(r"(?i)url\s*=\s*(.+)", stripped)
        if config_match:
            stripped = config_match.group(1).strip().strip("\"'")
        else:
            stripped = stripped.split()[0]
        if stripped:
            targets.append(clean_candidate(stripped))
    return targets


def _scan_tokens(tokens: list[str], command: str) -> tuple[bool, list[str]]:
    candidates: list[str] = []
    network_cmd = False   # a network tool actually invoked in command position
    active_tool = ""
    cmd_pos = True        # the next ordinary word is a command being executed
    loose = False         # a transparent prefix put us in fail-closed over-include
    skip_value = False
    target_value = False
    input_value = False
    for token in tokens:
        if token in {"|", "||", "&&", ";", "&"}:
            active_tool = ""
            cmd_pos = True
            loose = False
            skip_value = target_value = input_value = False
            continue
        if token in {">", ">>", "<", "2>", "2>>", "1>", "&>", "&>>"}:
            skip_value = True  # the following token is a redirect target file
            continue
        if target_value:
            candidates.append(clean_candidate(token))
            target_value = False
            cmd_pos = False
            continue
        if input_value:
            candidates.extend(targets_from_file(token))
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
            if token.startswith("-") or ASSIGN_RE.match(token):
                continue  # a prefix's own flag or NAME=value; stay at command pos
            if basename in PREFIX_COMMANDS:
                loose = True
                continue
            cmd_pos = False
            if basename in NETWORK_TOOLS:
                network_cmd = True
                active_tool = basename
                continue
            if basename in {"python", "python3"} and GENERIC_NETWORK_RE.search(command):
                network_cmd = True
                active_tool = basename
                continue
            # a non-network command; fall through with no active_tool set
        elif loose and basename in NETWORK_TOOLS:
            network_cmd = True
            active_tool = basename
            continue
        # Only interpret target/input/value flags while a network tool is the
        # active command; otherwise "-l"/"-d"/"-t" on plain commands (wc -l,
        # tr -d, sort -t) would be misread as targets or trigger file reads.
        if active_tool:
            if token in TARGET_FLAGS:
                target_value = True
                continue
            if token == "-d":
                if active_tool in DOMAIN_D_TOOLS:
                    target_value = True
                else:  # curl/sqlmap/wpscan: -d is request/POST data, not a host
                    skip_value = True
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
                candidates.append(cand)
                active_tool = ""
    return network_cmd, candidates


def extract(command: str) -> tuple[bool, list[str]]:
    url_candidates = [clean_candidate(value) for value in URL_RE.findall(command)]
    # Scan each newline-separated statement with fresh state so a network tool
    # on one line cannot leak `active_tool` onto the next (which would misread a
    # later dotted filename like `cat out.txt` as a host). If a quoted argument
    # spans lines, per-line shlex fails -> fall back to one whole-command scan.
    lines = command.splitlines() or [command]
    token_lists: list[list[str]] = []
    try:
        for line in lines:
            if line.strip():
                token_lists.append(shlex.split(line, posix=True))
    except ValueError:
        try:
            token_lists = [shlex.split(command, posix=True)]
        except ValueError as exc:
            if any(re.search(rf"\b{re.escape(tool)}\b", command) for tool in NETWORK_TOOLS):
                raise ConfigError(f"cannot parse network command: {exc}") from exc
            return False, list(dict.fromkeys(v for v in url_candidates if v))

    proxy_values = loopback_proxy_values(token_lists)
    candidates: list[str] = []
    for value in url_candidates:
        if proxy_values[value] > 0:
            proxy_values[value] -= 1
        else:
            candidates.append(value)

    network_seen = False
    for tokens in token_lists:
        seen, cands = _scan_tokens(tokens, command)
        network_seen = network_seen or seen
        candidates.extend(cands)
    return network_seen, list(dict.fromkeys(value for value in candidates if value))


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
        network_seen, candidates = extract(command)
        if not network_seen and not candidates:
            return 0
        if network_seen and not candidates:
            raise ConfigError("network command has no statically verifiable target; use explicit targets or an inspectable target file")
        yaml_path = resolve_engagement(None, root=ROOT)
        config = load_engagement(yaml_path)
        for candidate in candidates:
            allowed, host, reason = scope_decision(config, candidate)
            if not allowed:
                raise ConfigError(f"target {host!r} denied: {reason}")
    except ConfigError as exc:
        decision(str(exc), command)
    except Exception as exc:  # noqa: BLE001 - a scope guard must fail closed on ANY error
        decision(f"scope guard internal error ({type(exc).__name__}): {exc}", command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
