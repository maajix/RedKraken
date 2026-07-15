#!/usr/bin/env python3
"""mitmproxy addon that enforces engagement scope on every HTTP request."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from audit_event import append_event, utc_now  # noqa: E402
from harness_config import (  # noqa: E402
    ConfigError,
    load_engagement,
    pattern_matches,
    rate_policy,
    resolve_engagement,
    scope_decision,
)


def within_window(value: str) -> bool:
    if not value or value == "any":
        return True
    try:
        start_raw, end_raw = value.split("/", 1)
        start = datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_raw.replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("timezone required")
        current = datetime.now(start.tzinfo)
        return start <= current <= end
    except ValueError as exc:
        raise ConfigError(f"invalid time_window {value!r}: {exc}") from exc


class ScopeEnforcer:
    def __init__(self) -> None:
        self.error = ""
        self.directory: Path | None = None
        self.config: dict = {}
        self.tool = os.environ.get("PENTEST_PROXY_TOOL", "").strip()
        self.policy: dict[str, float | int] | None = None
        self.rate_lock = asyncio.Lock()
        self.tokens = 0.0
        self.updated = time.monotonic()
        self.concurrency: asyncio.BoundedSemaphore | None = None
        self.acquired: set[str] = set()
        try:
            yaml_path = resolve_engagement(None, root=ROOT)
            self.directory = yaml_path.parent
            self.config = load_engagement(yaml_path)
            self.policy = rate_policy(self.config, self.tool)
            if self.policy:
                self.tokens = float(self.policy["burst"])
                self.concurrency = asyncio.BoundedSemaphore(int(self.policy["max_concurrency"]))
        except ConfigError as exc:
            self.error = str(exc)

    def allowed_support(self, host: str) -> bool:
        for pattern in self.config.get("egress_support") or []:
            if pattern_matches(host, pattern):
                return True
        return False

    def audit(self, flow: http.HTTPFlow, allowed: bool, reason: str) -> None:
        if self.directory is None:
            return
        parsed = urlsplit(flow.request.pretty_url)
        query = parsed.query
        event = {
            "schema_version": 1,
            "ts": utc_now(),
            "event": "proxy-policy",
            "allowed": allowed,
            "reason": reason,
            "method": flow.request.method,
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "query_sha256": hashlib.sha256(query.encode()).hexdigest() if query else "",
            "proxy_tool": self.tool,
            "rate_limit_active": self.policy is not None,
        }
        append_event(self.directory, event)

    async def throttle(self) -> None:
        if not self.policy:
            return
        rate = float(self.policy["requests_per_second"])
        burst = float(self.policy["burst"])
        while True:
            async with self.rate_lock:
                now = time.monotonic()
                self.tokens = min(burst, self.tokens + max(0.0, now - self.updated) * rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / rate
            await asyncio.sleep(wait)

    def release(self, flow: http.HTTPFlow) -> None:
        if self.concurrency is not None and flow.id in self.acquired:
            self.acquired.remove(flow.id)
            self.concurrency.release()

    async def request(self, flow: http.HTTPFlow) -> None:
        allowed = False
        reason = self.error or "scope configuration unavailable"
        try:
            if self.error:
                raise ConfigError(self.error)
            if not within_window(str(self.config.get("time_window") or "any")):
                raise ConfigError("outside engagement time_window")
            allowed, host, reason = scope_decision(self.config, flow.request.pretty_url)
            if not allowed and self.allowed_support(host):
                allowed, reason = True, "matched egress_support"
        except ConfigError as exc:
            reason = str(exc)
        self.audit(flow, allowed, reason)
        if not allowed:
            flow.response = http.Response.make(
                451,
                f"Blocked by engagement scope: {reason}\n",
                {"Content-Type": "text/plain", "X-Pentest-Scope": "blocked"},
            )
            return
        if self.concurrency is not None:
            await self.concurrency.acquire()
            self.acquired.add(flow.id)
        await self.throttle()

    def response(self, flow: http.HTTPFlow) -> None:
        self.release(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self.release(flow)


addons = [ScopeEnforcer()]
