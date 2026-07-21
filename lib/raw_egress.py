#!/usr/bin/env python3
"""Gated raw-socket byte-transparent egress lane (RedKraken #19).

Framing-sensitive families -- request smuggling / HTTP desync / TE.CL /
connection-reuse -- cannot be tested through the shared scope proxy: mitmproxy
parses and re-serializes every message and rejects ambiguous framing with its
own 400, so the target never sees the mutation under test. This lane sends a
tool's *exact bytes* over raw TCP/TLS to an in-scope destination, with no HTTP
re-serialization, so the framing on the wire is the framing under test.

It is deliberately more powerful than the proxy path (arbitrary bytes to the
target) and is therefore gated behind TWO independent, fail-closed checks that
must both pass, plus scope:

1. an explicit operator toggle (``raw_egress_lane``), off by default;
2. the RoE authorization ``availability_impact_allowed`` -- byte-level framing
   manipulation can poison connection/response queues and affect availability;
3. the destination must be in scope, decided by the one shared policy
   (``harness_config.scope_decision``) -- never a forked check.

Confinement to in-scope destinations at the network layer is the L3/L4 boundary
of RedKraken #17 (see docs/adr/0001-egress-containment-boundary.md); this module
is the byte-transparent lane that boundary is designed to host. In the current
live engagement the lane stays denied: ``availability_impact_allowed`` is false
(RoE) and it is off by default -- so the family is blocked-pending-infra + RoE,
not exhausted.

The socket factory and audit sink are injected, so authorization and
byte-transparency are unit-tested without touching the network. The CLI is a
dry-run (authorize only) unless ``--send`` is given.
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol
from urllib.parse import urlsplit

from audit_event import append_event, resolve_directory, utc_now
from harness_config import (
    ConfigError,
    load_engagement,
    resolve_engagement,
    roe_authorizations,
    scope_decision,
)


ROOT = Path(__file__).resolve().parent.parent

TOGGLE_KEY = "raw_egress_lane"
RAW_EVENT = "raw-egress"
DEFAULT_TIMEOUT = 10.0
DEFAULT_READ_LIMIT = 65536


@dataclass(frozen=True)
class RawEgressDecision:
    allowed: bool
    reason: str
    host: str = ""
    port: int = 0
    tls: bool = False


class Connection(Protocol):
    def sendall(self, data: bytes) -> None: ...
    def recv(self, bufsize: int) -> bytes: ...
    def close(self) -> None: ...


def raw_egress_enabled(config: dict) -> bool:
    """Opt-in and fail-safe: only an explicit boolean ``True`` enables the lane."""
    return config.get(TOGGLE_KEY) is True


def split_target(target: str) -> tuple[str, int, bool]:
    """Parse ``host`` / ``host:port`` / ``scheme://host[:port]`` into host, port, tls."""
    parsed = urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname
    if not host:
        raise ConfigError(f"cannot determine host from target: {target}")
    tls = parsed.scheme == "https"
    try:
        port = parsed.port  # None when absent; ValueError when out of range
    except ValueError as exc:
        raise ConfigError(f"invalid port in target: {target}") from exc
    if port is None:
        port = 443 if tls else 80
    if not 1 <= port <= 65535:  # a literal 0 is invalid, not "unset"
        raise ConfigError(f"invalid port in target: {target}")
    return host, port, tls


def authorize(
    config: dict,
    target: str,
    *,
    scope: Callable[..., tuple[bool, str, str]] = scope_decision,
    roe: Callable[[dict], dict] = roe_authorizations,
) -> RawEgressDecision:
    """Decide whether the lane may egress to ``target``. Every gate fails closed."""
    if not raw_egress_enabled(config):
        return RawEgressDecision(False, "raw egress lane disabled (raw_egress_lane toggle off)")
    if not roe(config).get("availability_impact_allowed"):
        return RawEgressDecision(
            False, "raw egress lane requires availability_impact_allowed (RoE) to be granted"
        )
    allowed, host, reason = scope(config, target)
    if not allowed:
        return RawEgressDecision(False, f"destination out of scope: {reason}", host)
    _host, port, tls = split_target(target)
    return RawEgressDecision(True, "authorized", host, port, tls)


def open_connection(host: str, port: int, tls: bool, timeout: float) -> Connection:
    """Default socket factory; injected as ``connect`` so tests never open a socket."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if not tls:
        return raw
    context = ssl.create_default_context()
    return context.wrap_socket(raw, server_hostname=host)


def _audit_attempt(directory: Optional[Path], decision: RawEgressDecision, payload: bytes, audit) -> None:
    target_dir = directory or resolve_directory()
    if target_dir is None:
        return
    event = {
        "schema_version": 1,
        "ts": utc_now(),
        "event": RAW_EVENT,
        "host": decision.host,
        "port": decision.port,
        "tls": decision.tls,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
    }
    try:
        audit(target_dir, event)
    except (OSError, ValueError) as exc:  # auditing must not swallow the send path
        print(f"raw_egress: audit event skipped: {exc}", file=sys.stderr)


def send_raw(
    config: dict,
    target: str,
    payload: bytes,
    *,
    connect: Callable[..., Connection] = open_connection,
    audit=append_event,
    directory: Optional[Path] = None,
    timeout: float = DEFAULT_TIMEOUT,
    read_limit: int = DEFAULT_READ_LIMIT,
) -> bytes:
    """Send ``payload`` verbatim to an authorized in-scope target; return the reply.

    Raises ``ConfigError`` (fail closed) when any gate denies, before any socket
    is opened. On success the exact bytes are written with no re-serialization --
    that byte-transparency is the whole point of the lane.
    """
    decision = authorize(config, target)
    if not decision.allowed:
        raise ConfigError(f"raw egress denied: {decision.reason}")
    _audit_attempt(directory, decision, payload, audit)
    conn = connect(decision.host, decision.port, decision.tls, timeout)
    try:
        conn.sendall(payload)
        chunks: list[bytes] = []
        received = 0
        while received < read_limit:
            data = conn.recv(min(4096, read_limit - received))
            if not data:
                break
            chunks.append(data)
            received += len(data)
    finally:
        conn.close()
    return b"".join(chunks)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Gated raw byte-transparent egress lane")
    parser.add_argument("target", help="host, host:port, or scheme://host[:port]")
    parser.add_argument("payload", nargs="?", help="file with exact request bytes (default: stdin)")
    parser.add_argument("--engagement", dest="engagement")
    parser.add_argument("--send", action="store_true", help="actually transmit (default: dry-run authorize only)")
    args = parser.parse_args(argv[1:])
    try:
        yaml_path = resolve_engagement(args.engagement, root=ROOT)
        config = load_engagement(yaml_path)
    except ConfigError as exc:
        print(f"raw_egress: {exc}", file=sys.stderr)
        return 2
    decision = authorize(config, args.target)
    if not decision.allowed:
        print(f"DENIED {args.target} ({decision.reason})")
        return 1
    print(f"AUTHORIZED {decision.host}:{decision.port} tls={decision.tls}")
    if not args.send:
        print("dry-run (pass --send to transmit)")
        return 0
    payload = Path(args.payload).read_bytes() if args.payload else sys.stdin.buffer.read()
    try:
        response = send_raw(config, args.target, payload, directory=yaml_path.parent)
    except (ConfigError, OSError) as exc:
        print(f"raw_egress: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
