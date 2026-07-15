#!/usr/bin/env python3
"""Best-effort Bash target extraction backed by the strict scope parser."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from harness_config import ConfigError, load_engagement, resolve_engagement, scope_decision  # noqa: E402


NETWORK_TOOLS = {
    "amass", "curl", "dalfox", "dig", "dnsx", "feroxbuster", "ffuf", "gau",
    "gobuster", "grpcurl", "host", "httpx", "katana", "masscan", "mitmdump",
    "nc", "ncat", "nikto", "nmap", "nuclei", "openssl", "paramspider", "ping",
    "schemathesis", "socat", "sqlmap", "ssh", "subfinder", "telnet", "wget",
    "whatweb", "waybackurls", "wpscan", "wafw00f",
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


def decision(reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"SCOPE BLOCK: {reason}"[:500],
        }
    }
    print(json.dumps(payload, separators=(",", ":")))


def clean_candidate(value: str) -> str:
    return value.strip().strip("\"'").rstrip(",;)")


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
    network_seen = False
    active_tool = ""
    skip_value = False
    target_value = False
    input_value = False
    for token in tokens:
        if token in {"|", "||", "&&", ";"}:
            active_tool = ""
            skip_value = target_value = input_value = False
            continue
        if token in {">", ">>", "<", "2>", "2>>", "1>", "&>", "&>>"}:
            skip_value = True  # the following token is a redirect target file
            continue
        basename = os.path.basename(token)
        if basename in NETWORK_TOOLS:
            network_seen = True
            active_tool = basename
            continue
        if basename in {"python", "python3"} and GENERIC_NETWORK_RE.search(command):
            network_seen = True
            active_tool = basename
            continue
        if target_value:
            candidates.append(clean_candidate(token))
            target_value = False
            continue
        if input_value:
            candidates.extend(targets_from_file(token))
            input_value = False
            continue
        if skip_value:
            skip_value = False
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
    return network_seen, candidates


def extract(command: str) -> tuple[bool, list[str]]:
    candidates = [clean_candidate(value) for value in URL_RE.findall(command)]
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
            return False, list(dict.fromkeys(v for v in candidates if v))

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
        decision(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
