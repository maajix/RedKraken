#!/usr/bin/env python3
"""Gated, default-off egress containment (RedKraken #17, Layer 2).

Establishes a network-layer boundary so the agent's only outbound route is the
loopback scope proxy, and returns the proxy environment the agent shell should
run under. The existing fail-closed scope proxy and the single shared
scope-decision policy (``harness_config.scope_decision``) are reused unchanged:
the boundary confines egress at L3/L4 (there is no route out except the loopback
proxy port), while the proxy inspects, records, and decides host scope. Scope is
still decided in exactly one place -- the proxy -- so this module never forks the
policy.

OFF by default. With the ``egress_containment`` toggle off, ``provision_containment``
is a strict no-op returning an empty environment, and the runtime is identical to
today (non-breaking, opt-in).

Fails closed. When enabled, any missing prerequisite -- non-Linux host, not root,
``nft`` absent, or a rule-install failure -- raises ``ConfigError``. The launch
path treats that as a blocked run rather than degrading to open egress.

The privileged executor (``runner``), platform, uid probe, and PATH lookup are
injected, so the provisioning logic is unit-tested without standing up a real
firewall. The end-to-end guarantee (out-of-scope egress actually fails inside the
boundary) is covered by a separate privileged system test that skips when it
cannot obtain root. See docs/adr/0001-egress-containment-boundary.md.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from audit_event import utc_now
from harness_config import ConfigError


ROOT = Path(__file__).resolve().parent.parent

TOGGLE_KEY = "egress_containment"
DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 18080
CONTAINMENT_TABLE = "pentest_egress"
MECHANISM = "nftables-owner"
LAUNCH_EVENT = "containment-launch"
LOOPBACK_NO_PROXY = "127.0.0.1,::1,localhost"


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def run_privileged(argv: list[str], *, stdin: str | None = None) -> RunResult:
    """Default privileged executor; injected as ``runner`` so tests never shell out."""
    completed = subprocess.run(
        argv, input=stdin, text=True, capture_output=True, timeout=15, check=False
    )
    return RunResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class ContainmentResult:
    active: bool
    mechanism: str
    proxy_url: str
    env: dict[str, str] = field(default_factory=dict)
    table: str = ""
    note: str = ""


def containment_enabled(config: dict) -> bool:
    """The toggle is opt-in and fails safe: only an explicit ``true`` enables it."""
    return config.get(TOGGLE_KEY) is True


def proxy_url(host: str = DEFAULT_PROXY_HOST, port: int = DEFAULT_PROXY_PORT) -> str:
    return f"http://{host}:{port}"


def containment_env(url: str) -> dict[str, str]:
    """Proxy environment injected by default under containment.

    Sets both the harness variable existing tools consume (``PENTEST_PROXY``) and
    the standard proxy variables, so a known tool or an ad-hoc script is scoped
    without per-command wiring. Loopback is exempted (``NO_PROXY``) so the hop to
    the proxy itself is not recursively proxied.
    """
    return {
        "PENTEST_PROXY": url,
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "ALL_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "all_proxy": url,
        "NO_PROXY": LOOPBACK_NO_PROXY,
        "no_proxy": LOOPBACK_NO_PROXY,
    }


def nft_ruleset(table: str, uid: int, host: str, port: int) -> str:
    """Owner-match egress boundary for one uid.

    The only permitted *new* outbound flow for ``uid`` is to the loopback scope
    proxy; loopback and already-established flows pass; every other flow this uid
    emits is rejected. Traffic from any other uid (the proxy's own upstream
    included) is untouched. The rule is keyed on the destination *route* (loopback
    proxy), not on resolved in-scope IPs, so it never has to track DNS rotation --
    all host-vs-IP scope decisions remain the proxy's. ``flush table`` makes a
    re-provision atomically idempotent across a resumed engagement.
    """
    lines = [
        f"add table inet {table}",
        f"flush table inet {table}",
        f"add chain inet {table} output "
        "{ type filter hook output priority 0; policy accept; }",
        f"add rule inet {table} output meta skuid != {uid} accept",
        f"add rule inet {table} output oifname \"lo\" accept",
        f"add rule inet {table} output ct state established,related accept",
        f"add rule inet {table} output ip daddr {host} tcp dport {port} accept",
        f"add rule inet {table} output ip daddr 127.0.0.0/8 accept",
        f"add rule inet {table} output ip6 daddr ::1 accept",
        f"add rule inet {table} output reject with icmpx type admin-prohibited",
    ]
    return "\n".join(lines) + "\n"


def provision_containment(
    config: dict,
    directory: Path,
    *,
    host: str = DEFAULT_PROXY_HOST,
    port: int = DEFAULT_PROXY_PORT,
    uid: Optional[int] = None,
    runner: Callable[..., RunResult] = run_privileged,
    platform: str = sys.platform,
    geteuid: Callable[[], int] = os.geteuid,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> ContainmentResult:
    """The single seam the launch path depends on.

    Returns a :class:`ContainmentResult`; when the toggle is off it is a strict
    no-op (``active=False``, empty env, runner never called). When on, it installs
    the boundary via ``runner`` and returns the proxy environment, or raises
    ``ConfigError`` (fail closed) if any prerequisite is missing.
    """
    url = proxy_url(host, port)
    if not containment_enabled(config):
        return ContainmentResult(
            active=False,
            mechanism="disabled",
            proxy_url=url,
            note="egress_containment toggle off; runtime unchanged",
        )
    if not str(platform).startswith("linux"):
        raise ConfigError(
            "egress containment is Linux-only; refusing to run uncontained"
        )
    if geteuid() != 0:
        raise ConfigError(
            "egress containment requires root to install the egress boundary; "
            "refusing to run uncontained"
        )
    nft = which("nft")
    if not nft:
        raise ConfigError(
            "egress containment requires nftables (nft), which is not installed; "
            "refusing to run uncontained"
        )
    target_uid = os.getuid() if uid is None else uid
    ruleset = nft_ruleset(CONTAINMENT_TABLE, target_uid, host, port)
    result = runner([nft, "-f", "-"], stdin=ruleset)
    if result.returncode != 0:
        raise ConfigError(
            f"egress containment boundary install failed (nft rc={result.returncode}): "
            f"{result.stderr.strip()[:400]}"
        )
    return ContainmentResult(
        active=True,
        mechanism=MECHANISM,
        proxy_url=url,
        env=containment_env(url),
        table=CONTAINMENT_TABLE,
        note=f"nftables owner-match boundary for uid {target_uid}; sole egress is {url}",
    )


def containment_state(result: ContainmentResult) -> dict:
    """Serializable containment block persisted into run.json."""
    return {
        "active": result.active,
        "mechanism": result.mechanism,
        "proxy_url": result.proxy_url,
        "env": dict(result.env),
    }


def launch_event(result: ContainmentResult) -> dict:
    """Launch-time audit event recording whether containment was active."""
    return {
        "schema_version": 1,
        "ts": utc_now(),
        "event": LAUNCH_EVENT,
        "containment_active": result.active,
        "mechanism": result.mechanism,
        "proxy_url": result.proxy_url,
        "note": result.note,
    }
