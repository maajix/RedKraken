#!/usr/bin/env python3
"""Unit tests for lib/proxy_supervisor.py.

The supervisor's OS-spawning is injectable, so these drive the durable
behaviours -- audit-recency liveness, single-owner flock, respawn budget, the
respawn loop, and the PID-reuse-safe stale reap -- without real proxies.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import proxy_supervisor as ps  # noqa: E402


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


class FakeProc:
    def __init__(self, pid: int, code: int) -> None:
        self.pid = pid
        self._code = code
        self.terminated = False

    def wait(self) -> int:
        return self._code

    def terminate(self) -> None:
        self.terminated = True


class AuditRecencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)
        self.audit = self.directory / "audit.jsonl"

    def write_events(self, *events: dict) -> None:
        self.audit.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )

    def test_missing_audit_is_unhealthy(self) -> None:
        self.assertIsNone(ps.last_proxy_activity(self.directory))
        self.assertFalse(ps.proxy_healthy(self.directory, now=1000.0))

    def test_recent_proxy_event_is_healthy(self) -> None:
        self.write_events({"event": "proxy-policy", "ts": iso(950.0), "allowed": True})
        self.assertEqual(ps.last_proxy_activity(self.directory), 950.0)
        self.assertTrue(ps.proxy_healthy(self.directory, now=1000.0, window=120.0))

    def test_stale_proxy_event_is_unhealthy(self) -> None:
        self.write_events({"event": "proxy-policy", "ts": iso(500.0)})
        self.assertFalse(ps.proxy_healthy(self.directory, now=1000.0, window=120.0))

    def test_non_proxy_events_do_not_count_as_liveness(self) -> None:
        # A recent scope-block (from the PreToolUse guard) is not proxy traffic.
        self.write_events(
            {"event": "scope-block", "ts": iso(990.0)},
            {"event": "proxy-policy", "ts": iso(300.0)},
        )
        self.assertEqual(ps.last_proxy_activity(self.directory), 300.0)
        self.assertFalse(ps.proxy_healthy(self.directory, now=1000.0, window=120.0))

    def test_latest_proxy_event_wins(self) -> None:
        self.write_events(
            {"event": "proxy-policy", "ts": iso(100.0)},
            {"event": "proxy-policy", "ts": iso(980.0)},
        )
        self.assertEqual(ps.last_proxy_activity(self.directory), 980.0)


class OwnerLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "state" / "scope-proxy-18080.lock"

    def test_second_acquire_fails_then_succeeds_after_release(self) -> None:
        first = ps.OwnerLock(self.path)
        self.assertTrue(first.acquire())
        second = ps.OwnerLock(self.path)
        self.assertFalse(second.acquire())  # exactly one owner
        first.release()
        third = ps.OwnerLock(self.path)
        self.assertTrue(third.acquire())  # lock is reusable once freed
        third.release()

    def test_context_manager_releases(self) -> None:
        with ps.OwnerLock(self.path) as lock:
            self.assertTrue(lock.acquire())
        reacquired = ps.OwnerLock(self.path)
        self.assertTrue(reacquired.acquire())
        reacquired.release()


class RespawnPolicyTests(unittest.TestCase):
    def test_budget_stops_after_max_restarts_in_window(self) -> None:
        policy = ps.RespawnPolicy(max_restarts=3, window=60.0)
        for moment in (0.0, 1.0, 2.0):
            policy.record(moment)
        self.assertFalse(policy.should_restart(2.0))

    def test_old_restarts_fall_out_of_window(self) -> None:
        policy = ps.RespawnPolicy(max_restarts=3, window=60.0)
        for moment in (0.0, 1.0, 2.0):
            policy.record(moment)
        # 100s later the early restarts have aged out -> budget available again.
        self.assertTrue(policy.should_restart(100.0))

    def test_backoff_grows_and_caps(self) -> None:
        policy = ps.RespawnPolicy(base_backoff=0.5, max_backoff=4.0)
        policy.record(0.0)
        self.assertEqual(policy.backoff(0.0), 0.5)   # 1 recent -> base
        policy.record(0.0)
        self.assertEqual(policy.backoff(0.0), 1.0)   # 2 recent -> base*2
        for _ in range(8):
            policy.record(0.0)
        self.assertEqual(policy.backoff(0.0), 4.0)   # capped


class RunSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.engagement = Path(self.tempdir.name)
        self.calls: list[int] = []

    def spawner(self, code: int):
        def spawn(directory: Path, port: int, tool: str) -> FakeProc:
            pid = 1000 + len(self.calls)
            self.calls.append(pid)
            return FakeProc(pid, code)
        return spawn

    def test_respawns_until_crash_loop_budget_exhausted(self) -> None:
        rc = ps.run_supervisor(
            self.engagement, 18080, "test",
            spawn=self.spawner(code=1),
            clock=lambda: 0.0,          # all restarts land inside the window
            sleep=lambda _delay: None,
            log=lambda _message: None,
        )
        self.assertEqual(rc, 1)                       # gave up on crash loop
        self.assertEqual(len(self.calls), ps.MAX_RESTARTS)

    def test_bounded_cycles_return_clean_and_release_lock(self) -> None:
        rc = ps.run_supervisor(
            self.engagement, 18080, "test",
            spawn=self.spawner(code=0),
            clock=lambda: 0.0,
            sleep=lambda _delay: None,
            max_cycles=1,
            log=lambda _message: None,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.calls), 1)
        # Lock was released on exit, so a fresh supervisor can take over.
        successor = ps.OwnerLock(ps.owner_lock_path(self.engagement.resolve(), 18080))
        self.assertTrue(successor.acquire())
        successor.release()

    def test_does_not_spawn_when_another_supervisor_owns_the_proxy(self) -> None:
        holder = ps.OwnerLock(ps.owner_lock_path(self.engagement.resolve(), 18080))
        self.assertTrue(holder.acquire())
        try:
            rc = ps.run_supervisor(
                self.engagement, 18080, "test",
                spawn=self.spawner(code=0),
                sleep=lambda _delay: None,
                max_cycles=1,
                log=lambda _message: None,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(self.calls, [])          # exactly one: no second proxy
        finally:
            holder.release()

    def test_pidfile_written_for_running_child(self) -> None:
        ps.run_supervisor(
            self.engagement, 18080, "test",
            spawn=self.spawner(code=0),
            clock=lambda: 0.0,
            sleep=lambda _delay: None,
            max_cycles=1,
            log=lambda _message: None,
        )
        pidfile = ps.pid_path(self.engagement.resolve(), 18080)
        self.assertEqual(pidfile.read_text(encoding="utf-8"), str(self.calls[0]))


class ReapStaleProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)

    def test_no_pidfile_is_noop(self) -> None:
        self.assertFalse(ps.reap_stale_proxy(self.directory, 18080))

    def test_garbage_pidfile_is_noop(self) -> None:
        pidfile = ps.pid_path(self.directory, 18080)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text("not-a-pid", encoding="utf-8")
        self.assertFalse(ps.reap_stale_proxy(self.directory, 18080))

    def test_does_not_kill_a_reused_pid_that_is_not_our_proxy(self) -> None:
        # PID-reuse guard: a live PID whose /proc cmdline is not our mitmdump
        # must never be signalled.
        victim = subprocess.Popen(["sleep", "30"])
        self.addCleanup(victim.wait)
        self.addCleanup(victim.terminate)
        pidfile = ps.pid_path(self.directory, 18080)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(victim.pid), encoding="utf-8")
        self.assertFalse(ps.reap_stale_proxy(self.directory, 18080))
        self.assertIsNone(victim.poll())  # untouched


if __name__ == "__main__":
    unittest.main()
