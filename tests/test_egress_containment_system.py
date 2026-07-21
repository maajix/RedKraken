#!/usr/bin/env python3
"""Privileged system test for egress containment (RedKraken #17, Layer 2).

Unlike test_egress_containment.py (which injects the executor), this stands up
the REAL nftables boundary and proves the end-to-end guarantee: with the boundary
installed, an out-of-scope destination is unreachable while loopback (the scope
proxy's route) stays reachable. It requires Linux + root + nft, and skips cleanly
otherwise so the ordinary unprivileged suite stays green.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import egress_containment as ec  # noqa: E402


def _privileged() -> bool:
    return (
        sys.platform.startswith("linux")
        and hasattr(__import__("os"), "geteuid")
        and __import__("os").geteuid() == 0
        and shutil.which("nft") is not None
    )


@unittest.skipUnless(_privileged(), "needs Linux + root + nft; skipped when unprivileged")
class ContainmentBoundarySystemTest(unittest.TestCase):
    def tearDown(self) -> None:
        # Always tear the boundary down, even if an assertion failed mid-test.
        subprocess.run(
            ["nft", "delete", "table", "inet", ec.CONTAINMENT_TABLE],
            capture_output=True, text=True, check=False,
        )

    def test_boundary_blocks_out_of_scope_and_keeps_loopback(self) -> None:
        # Constrain THIS (root) uid so the running test process is inside the
        # boundary; the proxy would run under a different uid in production.
        import os

        result = ec.provision_containment(
            {"egress_containment": True}, ROOT, uid=os.getuid()
        )
        self.assertTrue(result.active)

        # The kernel accepted the generated ruleset (most likely regression point).
        listing = subprocess.run(
            ["nft", "list", "table", "inet", ec.CONTAINMENT_TABLE],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("dport 18080", listing.stdout)
        self.assertIn("reject", listing.stdout)

        # Out-of-scope egress fails at the network layer (TEST-NET-1, RFC 5737).
        with self.assertRaises(OSError):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocked:
                blocked.settimeout(3)
                blocked.connect(("192.0.2.1", 80))

        # Loopback (the proxy's route) is not rejected by the boundary: with no
        # listener it refuses the connection rather than being blocked, which is
        # observably different from the out-of-scope reject above.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as loop:
                loop.settimeout(3)
                loop.connect(("127.0.0.1", 18080))
        except ConnectionRefusedError:
            pass  # reached loopback, just nothing listening -- boundary allowed it
        except OSError as exc:  # pragma: no cover - would indicate the lo rule broke
            self.fail(f"loopback egress was blocked by the boundary: {exc}")


if __name__ == "__main__":
    unittest.main()
