#!/usr/bin/env python3
"""Verify an audit JSONL hash chain without echoing event contents."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from audit_event import event_digest  # noqa: E402


class VerificationResult(NamedTuple):
    valid: bool
    legacy_prefix: int
    line: int
    reason: str
    events: int


def broken(line: int, reason: str, legacy: int, events: int) -> VerificationResult:
    return VerificationResult(False, legacy, line, reason, events)


def verify_path(path: Path) -> VerificationResult:
    legacy = 0
    events = 0
    expected = "0" * 64
    chain_started = False
    try:
        handle = path.open("r", encoding="utf-8")
    except OSError as exc:
        raise OSError(f"cannot read audit file: {exc.strerror or 'read error'}") from exc
    with handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            events += 1
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                return broken(line_number, "invalid JSON", legacy, events)
            if not isinstance(event, dict):
                return broken(line_number, "event is not an object", legacy, events)
            stored = event.get("event_sha256")
            if stored is None:
                if chain_started:
                    return broken(line_number, "legacy event after chain start", legacy, events)
                legacy += 1
                expected = event_digest(event)
                continue
            if event.get("audit_chain_version") != 1:
                return broken(line_number, "unsupported audit chain version", legacy, events)
            if not chain_started:
                if legacy:
                    if event.get("chain_origin") != "legacy-anchor":
                        return broken(line_number, "missing legacy anchor marker", legacy, events)
                elif event.get("chain_origin") is not None:
                    return broken(line_number, "unexpected chain origin", legacy, events)
                chain_started = True
            if event.get("prev_sha256") != expected:
                return broken(line_number, "previous hash link mismatch", legacy, events)
            if event_digest(event) != stored:
                return broken(line_number, "event hash mismatch", legacy, events)
            expected = str(stored)
    return VerificationResult(True, legacy, 0, "ok", events)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-legacy-prefix", type=int)
    parser.add_argument("audit_file", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_path(args.audit_file)
    except OSError as exc:
        print(f"audit verification error: {exc}", file=sys.stderr)
        return 2
    if not result.valid:
        print(f"BROKEN line={result.line} reason={result.reason}")
        return 1
    if (
        args.expected_legacy_prefix is not None
        and result.legacy_prefix != args.expected_legacy_prefix
    ):
        print(
            "BROKEN line=0 reason=legacy prefix mismatch "
            f"expected={args.expected_legacy_prefix} actual={result.legacy_prefix}"
        )
        return 1
    print(f"VALID events={result.events} legacy_prefix={result.legacy_prefix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
