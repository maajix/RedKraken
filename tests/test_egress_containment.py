#!/usr/bin/env python3
"""Unit tests for lib/egress_containment.py (RedKraken #17, Layer 2).

The privileged executor, platform, uid probe, and PATH lookup are injected, so
these assert externally observable behaviour -- the environment the seam yields,
that it is a strict no-op when off, that it is idempotent across a resume, and
that it fails closed on a missing prerequisite -- without installing a real
firewall. The mechanism (nftables owner-match here) is replaceable without
touching these assertions except where they name the boundary explicitly.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import egress_containment as ec  # noqa: E402
from harness_config import ConfigError, scope_decision  # noqa: E402


class RecordingRunner:
    """Injected privileged executor; records calls, never shells out."""

    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, argv, *, stdin=None):
        self.calls.append((argv, stdin))
        return ec.RunResult(self.returncode, "", self.stderr)


def enabled_kwargs(runner, **overrides):
    """Provision arguments that simulate a Linux root host with nft present."""
    base = dict(
        runner=runner,
        platform="linux",
        geteuid=lambda: 0,
        which=lambda name: "/usr/sbin/nft",
        uid=4242,
    )
    base.update(overrides)
    return base


class ToggleOffTests(unittest.TestCase):
    def test_off_is_strict_noop(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment({}, ROOT, runner=runner, platform="linux")
        self.assertFalse(result.active)
        self.assertEqual(result.mechanism, "disabled")
        self.assertEqual(result.env, {})
        self.assertEqual(runner.calls, [])  # nothing privileged happened

    def test_off_when_key_is_false(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment(
            {"egress_containment": False}, ROOT, runner=runner, platform="linux"
        )
        self.assertFalse(result.active)
        self.assertEqual(runner.calls, [])

    def test_off_ignores_non_true_truthy_values(self) -> None:
        # Only an explicit boolean True opts in; a stray string must not enable it.
        runner = RecordingRunner()
        result = ec.provision_containment(
            {"egress_containment": "yes"}, ROOT, runner=runner, platform="linux"
        )
        self.assertFalse(result.active)
        self.assertEqual(runner.calls, [])


class ProvisionOnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {"egress_containment": True}

    def test_active_yields_loopback_proxy_environment(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment(self.config, ROOT, **enabled_kwargs(runner))
        self.assertTrue(result.active)
        self.assertEqual(result.mechanism, ec.MECHANISM)
        url = "http://127.0.0.1:18080"
        for var in ("PENTEST_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            self.assertEqual(result.env[var], url, var)
        # Loopback is exempted so the hop to the proxy is not recursively proxied.
        self.assertIn("127.0.0.1", result.env["NO_PROXY"])
        self.assertIn("localhost", result.env["no_proxy"])

    def test_custom_port_flows_into_env_and_rule(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment(
            self.config, ROOT, **enabled_kwargs(runner, port=9999)
        )
        self.assertEqual(result.env["PENTEST_PROXY"], "http://127.0.0.1:9999")
        _argv, script = runner.calls[0]
        self.assertIn("tcp dport 9999", script)

    def test_boundary_installed_via_nft(self) -> None:
        runner = RecordingRunner()
        ec.provision_containment(self.config, ROOT, **enabled_kwargs(runner))
        self.assertEqual(len(runner.calls), 1)
        argv, script = runner.calls[0]
        self.assertEqual(argv[0], "/usr/sbin/nft")
        self.assertIn("-f", argv)
        # Only the agent uid is constrained; its sole new egress is the proxy;
        # everything else it emits is rejected.
        self.assertIn("meta skuid != 4242 accept", script)
        self.assertIn("tcp dport 18080", script)
        self.assertIn("reject", script)

    def test_reprovision_is_idempotent(self) -> None:
        runner = RecordingRunner()
        first = ec.provision_containment(self.config, ROOT, **enabled_kwargs(runner))
        second = ec.provision_containment(self.config, ROOT, **enabled_kwargs(runner))
        self.assertEqual(first.env, second.env)
        # An atomic flush+recreate makes a resumed engagement re-establish the
        # same boundary without stacking duplicate rules.
        for _argv, script in runner.calls:
            self.assertIn(f"flush table inet {ec.CONTAINMENT_TABLE}", script)


class FailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {"egress_containment": True}

    def test_non_linux_fails_closed(self) -> None:
        runner = RecordingRunner()
        with self.assertRaises(ConfigError):
            ec.provision_containment(
                self.config, ROOT, **enabled_kwargs(runner, platform="darwin")
            )
        self.assertEqual(runner.calls, [])  # never touched the network

    def test_non_root_fails_closed(self) -> None:
        runner = RecordingRunner()
        with self.assertRaises(ConfigError):
            ec.provision_containment(
                self.config, ROOT, **enabled_kwargs(runner, geteuid=lambda: 1000)
            )
        self.assertEqual(runner.calls, [])

    def test_missing_nft_fails_closed(self) -> None:
        runner = RecordingRunner()
        with self.assertRaises(ConfigError):
            ec.provision_containment(
                self.config, ROOT, **enabled_kwargs(runner, which=lambda name: None)
            )
        self.assertEqual(runner.calls, [])

    def test_rule_install_failure_fails_closed(self) -> None:
        runner = RecordingRunner(returncode=1, stderr="permission denied")
        with self.assertRaises(ConfigError) as caught:
            ec.provision_containment(self.config, ROOT, **enabled_kwargs(runner))
        self.assertIn("permission denied", str(caught.exception))


class AuditAndStateTests(unittest.TestCase):
    def test_launch_event_records_inactive(self) -> None:
        result = ec.provision_containment({}, ROOT, platform="linux")
        event = ec.launch_event(result)
        self.assertEqual(event["event"], ec.LAUNCH_EVENT)
        self.assertFalse(event["containment_active"])
        self.assertEqual(event["mechanism"], "disabled")

    def test_launch_event_records_active(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment(
            {"egress_containment": True}, ROOT, **enabled_kwargs(runner)
        )
        event = ec.launch_event(result)
        self.assertTrue(event["containment_active"])
        self.assertEqual(event["mechanism"], ec.MECHANISM)
        self.assertEqual(event["proxy_url"], "http://127.0.0.1:18080")

    def test_containment_state_is_serializable_block(self) -> None:
        runner = RecordingRunner()
        result = ec.provision_containment(
            {"egress_containment": True}, ROOT, **enabled_kwargs(runner)
        )
        state = ec.containment_state(result)
        self.assertEqual(
            set(state), {"active", "mechanism", "proxy_url", "env"}
        )
        self.assertTrue(state["active"])
        self.assertEqual(state["env"]["PENTEST_PROXY"], "http://127.0.0.1:18080")


class PolicyReuseTests(unittest.TestCase):
    """The boundary does not fork scope: host scope stays the shared policy."""

    def test_shared_scope_policy_still_decides_host_scope(self) -> None:
        config = {"targets": ["app.example.com"], "out_of_scope": ["evil.other.org"]}
        allowed_in, _host, _r = scope_decision(config, "https://app.example.com/x")
        allowed_out, _host2, _r2 = scope_decision(config, "https://evil.other.org/x")
        self.assertTrue(allowed_in)
        self.assertFalse(allowed_out)


if __name__ == "__main__":
    unittest.main()
