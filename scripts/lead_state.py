#!/usr/bin/env python3
"""Manage durable lead, coverage, and convergence state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from lead_store import LeadState, LeadStateError  # noqa: E402


def _directory(explicit: str | None) -> Path:
    value = explicit or os.environ.get("PENTEST_ENGAGEMENT_DIR")
    if not value:
        raise LeadStateError("pass --engagement or set PENTEST_ENGAGEMENT_DIR")
    return Path(value).expanduser().resolve()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--engagement")
    commands = root.add_subparsers(dest="command", required=True)

    upsert = commands.add_parser("upsert")
    upsert.add_argument("--json", required=True)

    lease = commands.add_parser("lease")
    lease.add_argument("--worker", required=True)
    lease.add_argument("--lease-seconds", type=int, default=300)

    complete = commands.add_parser("complete")
    complete.add_argument("lead_id")
    complete.add_argument("--worker", required=True)
    complete.add_argument("--outcome", choices=("completed", "exhausted", "blocked"), required=True)
    complete.add_argument("--evidence", action="append", default=[])

    coverage = commands.add_parser("coverage")
    coverage.add_argument(
        "--dimension", choices=("endpoint", "workflow", "family", "scenario"), required=True
    )
    coverage.add_argument("--key", required=True)
    coverage.add_argument(
        "--status",
        choices=("tested", "exhausted", "blocked", "not-applicable", "not-tested"),
        required=True,
    )
    coverage.add_argument("--reason", default="")

    configure = commands.add_parser("configure")
    configure.add_argument("--max-iterations", type=int)
    configure.add_argument("--max-no-progress-rounds", type=int)
    configure.add_argument("--max-attempts", type=int)
    configure.add_argument("--max-requests", type=int)
    configure.add_argument("--max-seconds", type=int)

    request = commands.add_parser("request")
    request.add_argument("--count", type=int, default=1)

    iteration = commands.add_parser("iteration")
    progress = iteration.add_mutually_exclusive_group()
    progress.add_argument("--progress", action="store_true")
    progress.add_argument("--no-progress", action="store_true")
    iteration.add_argument("--progress-count", type=int)
    iteration.add_argument("--surface-delta", type=int, default=0)

    commands.add_parser("status")
    commands.add_parser("snapshot")
    return root


def run(args: argparse.Namespace) -> tuple[Any, int]:
    store = LeadState(_directory(args.engagement))
    if args.command == "upsert":
        return store.upsert_lead(json.loads(args.json)), 0
    if args.command == "lease":
        return store.lease_next(args.worker, args.lease_seconds), 0
    if args.command == "complete":
        return store.complete_lead(args.lead_id, args.worker, args.outcome, args.evidence), 0
    if args.command == "coverage":
        return store.record_coverage(args.dimension, args.key, args.status, args.reason), 0
    if args.command == "configure":
        values = {
            key: value
            for key, value in {
                "max_iterations": args.max_iterations,
                "max_no_progress_rounds": args.max_no_progress_rounds,
                "max_attempts": args.max_attempts,
                "max_requests": args.max_requests,
                "max_seconds": args.max_seconds,
            }.items()
            if value is not None
        }
        return store.configure_loop(**values), 0
    if args.command == "request":
        return store.record_requests(args.count), 0
    if args.command == "iteration":
        if args.progress_count is not None and (args.progress or args.no_progress):
            raise LeadStateError("use progress counts or legacy progress flags, not both")
        progress_count = args.progress_count
        if progress_count is None:
            progress_count = 1 if args.progress else 0
        return store.record_iteration(
            progress_count=progress_count,
            surface_delta=args.surface_delta,
        ), 0
    if args.command == "status":
        result = store.can_stop()
        return result, 0 if result["allowed"] else 3
    return store.snapshot(), 0


def main(argv: list[str]) -> int:
    try:
        result, code = run(parser().parse_args(argv[1:]))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return code
    except (LeadStateError, json.JSONDecodeError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
