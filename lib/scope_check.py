#!/usr/bin/env python3
"""Authoritative deny-by-default scope decision CLI."""

from __future__ import annotations

import sys
from pathlib import Path

from harness_config import ConfigError, load_engagement, resolve_engagement, scope_decision


ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    value = argv[1] if len(argv) > 1 else ""
    explicit = argv[2] if len(argv) > 2 else None
    try:
        yaml_path = resolve_engagement(explicit, root=ROOT)
        allowed, host, reason = scope_decision(load_engagement(yaml_path), value)
    except ConfigError as exc:
        print(f"OUT_OF_SCOPE {value.strip()} ({exc})")
        return 1
    if allowed:
        print(f"IN_SCOPE {host}")
        return 0
    print(f"OUT_OF_SCOPE {host} ({reason})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
