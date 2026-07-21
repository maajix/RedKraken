#!/usr/bin/env python3
"""Durable, namespace-robust supervisor for the engagement scope proxy.

Root cause it fixes: ``start_scope_proxy.sh`` used an unsupervised foreground
``exec mitmdump``, so the proxy's lifetime was tied to the launching agent
context.  When that context exited the proxy died mid-run and traffic escaped
scope enforcement until a human hand-restarted it (the live run lost PID 893020
this way).  Interim ``ss`` idempotency only stops a *second* start from crashing
the first -- it adds no auto-recovery.

This module supervises the proxy so it:
  (a) outlives its launcher -- the shell starts THIS detached via ``setsid``;
  (b) auto-respawns when the mitmdump child exits, bounded by a crash-loop
      budget so a proxy that cannot stay up stops thrashing and surfaces;
  (c) is guarded by a single-owner ``flock`` so exactly one supervisor runs per
      engagement+port (the lock frees automatically if the supervisor dies);
  (d) exposes a liveness probe based on AUDIT RECENCY, never ``ps``/``ss`` --
      under the #17 network-namespace future (and today under the command
      sandbox) a socket/process probe goes blind to the proxy and yields
      spurious "down" reads that trigger needless restarts.

The OS-spawning parts are injectable so the supervision logic (lock, respawn
budget, health probe, the loop itself) is unit-testable without real processes.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol


ROOT = Path(__file__).resolve().parent.parent

PROXY_EVENT = "proxy-policy"
DEFAULT_HEALTH_WINDOW = 120.0   # seconds of audit silence before "unhealthy"
MAX_AUDIT_SCAN_BYTES = 1_000_000
# Crash-loop guard: more than MAX_RESTARTS respawns inside RESTART_WINDOW means
# the proxy cannot stay up -- stop and surface rather than thrash forever.
MAX_RESTARTS = 5
RESTART_WINDOW = 60.0
BASE_BACKOFF = 0.5
MAX_BACKOFF = 30.0


# --------------------------------------------------------------------------- #
# Audit-recency liveness (namespace-robust; never ps/ss).
# --------------------------------------------------------------------------- #
def _parse_ts(value: str) -> float | None:
    """Epoch seconds for an ISO-8601 audit timestamp, or None."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def last_proxy_activity(directory: Path, *, max_scan_bytes: int = MAX_AUDIT_SCAN_BYTES) -> float | None:
    """Epoch seconds of the most recent proxy-policy event in audit.jsonl.

    Scans only the tail so a long-running engagement's audit log stays cheap.
    Returns None when the log is absent, unreadable, or has no proxy events.
    """
    audit = directory / "audit.jsonl"
    try:
        size = audit.stat().st_size
        with audit.open("rb") as handle:
            if size > max_scan_bytes:
                handle.seek(size - max_scan_bytes)
                handle.readline()  # drop the partial first line after seeking
            lines = handle.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped or PROXY_EVENT not in stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == PROXY_EVENT:
            timestamp = _parse_ts(str(event.get("ts", "")))
            if timestamp is not None:
                return timestamp
    return None


def proxy_healthy(
    directory: Path, *, now: float | None = None, window: float = DEFAULT_HEALTH_WINDOW
) -> bool:
    """True iff the proxy appended a flow event within ``window`` seconds.

    Passive: needs no probe request and no socket/process visibility, so it
    stays correct inside a network namespace where ss/ps would read blind.
    """
    last = last_proxy_activity(directory)
    if last is None:
        return False
    current = time.time() if now is None else now
    return (current - last) <= window


# --------------------------------------------------------------------------- #
# Single-owner lock: exactly one supervisor per engagement+port.
# --------------------------------------------------------------------------- #
def owner_lock_path(directory: Path, port: int) -> Path:
    return directory / "state" / f"scope-proxy-{port}.lock"


def pid_path(directory: Path, port: int) -> Path:
    return directory / "state" / f"scope-proxy-{port}.pid"


class OwnerLock:
    """Advisory ``flock`` marking a supervisor as the sole owner of a proxy.

    flock is tied to the open file description, so the kernel releases it
    automatically when the owning process dies -- a crashed supervisor never
    wedges the next one out.  Acquisition is non-blocking: a second supervisor
    simply fails to acquire and exits, giving the "exactly one" guarantee
    without any socket/process probe.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is not None:
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._handle.close()
                self._handle = None

    def __enter__(self) -> "OwnerLock":
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


# --------------------------------------------------------------------------- #
# Respawn budget: exponential backoff with a crash-loop ceiling.
# --------------------------------------------------------------------------- #
class RespawnPolicy:
    def __init__(
        self,
        *,
        max_restarts: int = MAX_RESTARTS,
        window: float = RESTART_WINDOW,
        base_backoff: float = BASE_BACKOFF,
        max_backoff: float = MAX_BACKOFF,
    ) -> None:
        self.max_restarts = max_restarts
        self.window = window
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._restarts: list[float] = []

    def record(self, when: float) -> None:
        self._restarts.append(when)

    def recent(self, now: float) -> int:
        return sum(1 for when in self._restarts if now - when <= self.window)

    def should_restart(self, now: float) -> bool:
        return self.recent(now) < self.max_restarts

    def backoff(self, now: float) -> float:
        exponent = max(0, self.recent(now) - 1)
        return min(self.max_backoff, self.base_backoff * (2 ** exponent))


# --------------------------------------------------------------------------- #
# Supervision loop.
# --------------------------------------------------------------------------- #
class SpawnedProcess(Protocol):
    pid: int

    def wait(self) -> int: ...

    def terminate(self) -> None: ...


def _proc_cmdline(pid: int) -> str:
    """The target process's argv joined by spaces, or '' if unreadable.

    Reads ``/proc/<pid>/cmdline`` -- namespace-local and cheap, so unlike ss/ps
    it stays valid where the supervisor and its child share a PID namespace.
    """
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def reap_stale_proxy(directory: Path, port: int, *, sig: int = signal.SIGTERM) -> bool:
    """Best-effort terminate a proxy left by a prior, crashed supervisor.

    A supervisor killed with SIGKILL cannot stop its mitmdump child, orphaning a
    process that still holds the port so the next supervisor's mitmdump cannot
    bind.  On startup we SIGTERM the recorded PID -- but only after confirming
    via /proc that it is still OUR mitmdump (guards against PID reuse).  Returns
    True when a stale proxy was signalled.
    """
    pidfile = pid_path(directory, port)
    try:
        recorded = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    if recorded <= 1 or recorded == os.getpid():
        return False
    cmdline = _proc_cmdline(recorded)
    if "mitmdump" not in cmdline or "scope_proxy.py" not in cmdline:
        return False
    try:
        os.kill(recorded, sig)
    except OSError:
        return False
    return True


def _write_pid(directory: Path, port: int, pid: int) -> None:
    path = pid_path(directory, port)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def spawn_mitmdump(directory: Path, port: int, tool: str) -> subprocess.Popen:
    """Launch mitmdump as a child, logging to the engagement state dir."""
    logfile = directory / "state" / f"scope-proxy-{port}.log"
    logfile.parent.mkdir(parents=True, exist_ok=True)
    environment = {
        **os.environ,
        "PENTEST_ENGAGEMENT_DIR": str(directory),
        "PENTEST_PROXY_TOOL": tool,
    }
    command = [
        "mitmdump",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "block_global=false",
        "-s", str(ROOT / "lib" / "scope_proxy.py"),
    ]
    handle = logfile.open("a")
    return subprocess.Popen(
        command,
        stdout=handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=environment,
    )


def run_supervisor(
    engagement: Path,
    port: int,
    tool: str,
    *,
    spawn: Callable[[Path, int, str], SpawnedProcess] = spawn_mitmdump,
    lock: OwnerLock | None = None,
    policy: RespawnPolicy | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    max_cycles: int | None = None,
    log: Callable[[str], None] = lambda message: None,
) -> int:
    """Own the proxy for one engagement+port and keep it alive.

    Returns 0 on a clean stop (or when another supervisor already owns it) and 1
    when the crash-loop budget is exhausted.  ``spawn``/``clock``/``sleep`` are
    injectable so the loop is deterministically testable without real processes.
    """
    directory = engagement.resolve()
    owner = lock or OwnerLock(owner_lock_path(directory, port))
    if not owner.acquire():
        log(f"another supervisor already owns proxy for {directory} :{port}; exiting")
        return 0
    budget = policy or RespawnPolicy()
    child: SpawnedProcess | None = None

    def _handle_signal(signum: int, _frame: object) -> None:
        if child is not None:
            try:
                child.terminate()
            except Exception:  # noqa: BLE001 - shutting down regardless
                pass
        owner.release()
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
    except (ValueError, OSError):
        pass  # not on the main thread (e.g. under a test runner) -- skip handlers

    try:
        reap_stale_proxy(directory, port)
        cycles = 0
        while max_cycles is None or cycles < max_cycles:
            child = spawn(directory, port, tool)
            _write_pid(directory, port, child.pid)
            log(f"proxy started pid={child.pid} port={port}")
            code = child.wait()
            child = None
            now = clock()
            budget.record(now)
            log(f"proxy exited code={code} port={port}")
            if not budget.should_restart(now):
                log("proxy restart budget exhausted (crash loop); supervisor giving up")
                return 1
            delay = budget.backoff(now)
            log(f"respawning in {delay:.1f}s")
            sleep(delay)
            cycles += 1
        return 0
    finally:
        owner.release()


def _cmd_supervise(args: argparse.Namespace) -> int:
    def log(message: str) -> None:
        print(f"[proxy-supervisor] {message}", file=sys.stderr, flush=True)

    return run_supervisor(Path(args.engagement), args.port, args.tool, log=log)


def _cmd_health(args: argparse.Namespace) -> int:
    healthy = proxy_healthy(Path(args.engagement).resolve(), window=args.window)
    print("healthy" if healthy else "unhealthy")
    return 0 if healthy else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scope-proxy supervisor")
    sub = parser.add_subparsers(dest="command", required=True)

    supervise = sub.add_parser("supervise", help="own and keep the proxy alive")
    supervise.add_argument("engagement")
    supervise.add_argument("port", type=int)
    supervise.add_argument("tool", nargs="?", default="")
    supervise.set_defaults(func=_cmd_supervise)

    health = sub.add_parser("health", help="audit-recency liveness probe")
    health.add_argument("engagement")
    health.add_argument("--window", type=float, default=DEFAULT_HEALTH_WINDOW)
    health.set_defaults(func=_cmd_health)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
