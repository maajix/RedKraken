#!/usr/bin/env python3
"""Unit tests for lib/raw_egress.py (RedKraken #19).

The socket factory and audit sink are injected, so these assert externally
observable behaviour -- the two independent fail-closed gates plus scope, and
that authorized bytes reach the wire verbatim (the byte-transparency the lane
exists to provide) -- without opening a socket. A denied decision must never
reach the socket factory at all.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import raw_egress as re  # noqa: E402
from harness_config import ConfigError  # noqa: E402


# A deliberately ambiguous request (conflicting Content-Length / Transfer-Encoding)
# -- exactly what a parsing proxy would reject or rewrite, and what must survive
# byte-for-byte on this lane.
SMUGGLE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: app.example.com\r\n"
    b"Content-Length: 6\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"0\r\n\r\nG"
)

BASE = {"targets": ["app.example.com"], "out_of_scope": ["evil.other.org"]}


def cfg(**overrides):
    return {**BASE, **overrides}


def enabled(**overrides):
    """A config where both gates are open: lane on + availability impact allowed."""
    return cfg(raw_egress_lane=True, availability_impact_allowed=True, **overrides)


class FakeConn:
    def __init__(self, response: bytes = b"HTTP/1.1 200 OK\r\n\r\n") -> None:
        self.sent = b""
        self._response = response
        self._served = False
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, bufsize: int) -> bytes:
        if self._served:
            return b""
        self._served = True
        return self._response

    def close(self) -> None:
        self.closed = True


class Harness:
    """Injectable connect + audit that record calls without any I/O."""

    def __init__(self, conn: FakeConn | None = None) -> None:
        self.conn = conn or FakeConn()
        self.connects: list[tuple[str, int, bool]] = []
        self.events: list[dict] = []

    def connect(self, host, port, tls, timeout):
        self.connects.append((host, port, tls))
        return self.conn

    def audit(self, directory, event):
        self.events.append(event)


class AuthorizeGateTests(unittest.TestCase):
    def test_lane_off_is_denied(self) -> None:
        # Even with RoE granted and an in-scope target, the toggle must gate.
        decision = re.authorize(
            cfg(availability_impact_allowed=True), "https://app.example.com/"
        )
        self.assertFalse(decision.allowed)
        self.assertIn("toggle off", decision.reason)

    def test_missing_both_roe_gates_is_denied(self) -> None:
        # Lane on, but neither RoE authorization granted -> fail closed, and the
        # reason names both acceptable paths.
        decision = re.authorize(cfg(raw_egress_lane=True), "https://app.example.com/")
        self.assertFalse(decision.allowed)
        self.assertIn("availability_impact_allowed", decision.reason)
        self.assertIn("raw_egress_self_contained", decision.reason)

    def test_self_contained_gate_authorizes_without_availability(self) -> None:
        # The narrow path: non-availability framing tests are authorized by
        # raw_egress_self_contained alone, with availability impact still denied.
        decision = re.authorize(
            cfg(raw_egress_lane=True, raw_egress_self_contained=True),
            "https://app.example.com/",
        )
        self.assertTrue(decision.allowed)

    def test_self_contained_without_lane_toggle_is_denied(self) -> None:
        # The RoE authorization never substitutes for the operator opt-in toggle.
        decision = re.authorize(
            cfg(raw_egress_self_contained=True), "https://app.example.com/"
        )
        self.assertFalse(decision.allowed)
        self.assertIn("toggle off", decision.reason)

    def test_self_contained_still_gated_by_scope(self) -> None:
        decision = re.authorize(
            cfg(raw_egress_lane=True, raw_egress_self_contained=True),
            "https://evil.other.org/",
        )
        self.assertFalse(decision.allowed)
        self.assertIn("out of scope", decision.reason)

    def test_out_of_scope_is_denied(self) -> None:
        decision = re.authorize(enabled(), "https://evil.other.org/")
        self.assertFalse(decision.allowed)
        self.assertIn("out of scope", decision.reason)

    def test_in_scope_with_both_gates_open_is_authorized(self) -> None:
        decision = re.authorize(enabled(), "https://app.example.com:8443/x")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.host, "app.example.com")
        self.assertEqual(decision.port, 8443)
        self.assertTrue(decision.tls)


class SplitTargetTests(unittest.TestCase):
    def test_bare_host_defaults_to_plain_http_80(self) -> None:
        self.assertEqual(re.split_target("app.example.com"), ("app.example.com", 80, False))

    def test_host_port(self) -> None:
        self.assertEqual(re.split_target("app.example.com:8080"), ("app.example.com", 8080, False))

    def test_https_url_defaults_to_443_tls(self) -> None:
        self.assertEqual(re.split_target("https://app.example.com/p"), ("app.example.com", 443, True))

    def test_invalid_port_raises(self) -> None:
        with self.assertRaises(ConfigError):
            re.split_target("app.example.com:0")


class SendRawTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)

    def test_denied_never_opens_a_socket(self) -> None:
        harness = Harness()
        with self.assertRaises(ConfigError):
            re.send_raw(
                cfg(raw_egress_lane=True),  # RoE still withheld -> denied
                "https://app.example.com/",
                SMUGGLE,
                connect=harness.connect,
                audit=harness.audit,
                directory=self.directory,
            )
        self.assertEqual(harness.connects, [])   # fail closed: no egress
        self.assertEqual(harness.events, [])      # nothing audited for a denied attempt

    def test_authorized_send_is_byte_transparent(self) -> None:
        harness = Harness(FakeConn(b"HTTP/1.1 400 Bad Request\r\n\r\n"))
        response = re.send_raw(
            enabled(),
            "app.example.com:80",
            SMUGGLE,
            connect=harness.connect,
            audit=harness.audit,
            directory=self.directory,
        )
        # Connected to the scoped host/port; exact bytes on the wire, unmodified.
        self.assertEqual(harness.connects, [("app.example.com", 80, False)])
        self.assertEqual(harness.conn.sent, SMUGGLE)
        self.assertTrue(harness.conn.closed)
        self.assertEqual(response, b"HTTP/1.1 400 Bad Request\r\n\r\n")

    def test_authorized_send_audits_without_storing_raw_payload(self) -> None:
        harness = Harness()
        re.send_raw(
            enabled(),
            "https://app.example.com/",
            SMUGGLE,
            connect=harness.connect,
            audit=harness.audit,
            directory=self.directory,
        )
        self.assertEqual(len(harness.events), 1)
        event = harness.events[0]
        self.assertEqual(event["event"], re.RAW_EVENT)
        self.assertEqual(event["host"], "app.example.com")
        self.assertEqual(event["port"], 443)
        self.assertTrue(event["tls"])
        self.assertEqual(event["payload_bytes"], len(SMUGGLE))
        self.assertEqual(len(event["payload_sha256"]), 64)
        # The raw request bytes are hashed, never stored verbatim.
        self.assertNotIn(b"Transfer-Encoding".decode(), str(event))


if __name__ == "__main__":
    unittest.main()
