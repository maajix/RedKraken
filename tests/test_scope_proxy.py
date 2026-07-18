#!/usr/bin/env python3
"""Cancellation and lifecycle regression tests for the scope proxy addon."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCOPE_PROXY = ROOT / "lib" / "scope_proxy.py"


class Request:
    def __init__(self, url: str) -> None:
        self.pretty_url = url
        self.method = "GET"
        self.headers: dict[str, str] = {}


class Flow:
    def __init__(self, flow_id: str) -> None:
        self.id = flow_id
        self.request = Request("http://127.0.0.1/")
        self.response = None


def load_scope_proxy(engagement: Path):
    """Load the addon with the small mitmproxy surface needed by these tests."""
    http = types.ModuleType("mitmproxy.http")
    http.HTTPFlow = object
    http.Response = types.SimpleNamespace(make=lambda *args, **kwargs: (args, kwargs))
    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.http = http

    spec = importlib.util.spec_from_file_location("scope_proxy_under_test", SCOPE_PROXY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with (
        mock.patch.dict(sys.modules, {"mitmproxy": mitmproxy, "mitmproxy.http": http}),
        mock.patch.dict(os.environ, {"PENTEST_ENGAGEMENT_DIR": str(engagement)}),
    ):
        spec.loader.exec_module(module)
    return module


class ScopeProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.engagement = Path(self.tempdir.name)
        (self.engagement / "engagement.yaml").write_text(
            "targets:\n"
            "  - 127.0.0.1\n"
            "out_of_scope: []\n"
            "rate_limit_enabled: true\n"
            "rate_limit:\n"
            "  requests_per_second: 100\n"
            "  burst: 1\n"
            "  max_concurrency: 1\n"
            "time_window: any\n",
            encoding="utf-8",
        )

    def test_error_hook_remains_callable_after_initialization(self) -> None:
        addon = load_scope_proxy(self.engagement).addons[0]

        self.assertTrue(callable(addon.error))

    def test_cancellation_during_throttle_releases_concurrency_permit(self) -> None:
        async def exercise() -> None:
            addon = load_scope_proxy(self.engagement).addons[0]
            assert addon.policy is not None and addon.concurrency is not None
            addon.policy["requests_per_second"] = 0.01
            addon.tokens = 0.0
            addon.updated = time.monotonic()
            flow = Flow("cancelled-flow")

            task = asyncio.create_task(addon.request(flow))
            while flow.id not in addon.acquired:
                await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            self.assertNotIn(flow.id, addon.acquired)
            self.assertFalse(addon.concurrency.locked())

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
