#!/usr/bin/env python3
"""Open a campaign and return its durable state, next work, and outcome."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from campaign_coordinator import CampaignCoordinator, CampaignEventError  # noqa: E402
from lead_store import LeadStateError  # noqa: E402


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--engagement", required=True)
    command.add_argument("--event")
    return command


def main(argv: list[str]) -> int:
    try:
        args = parser().parse_args(argv[1:])
        event = json.loads(args.event) if args.event is not None else None
        response = CampaignCoordinator(args.engagement).respond(event)
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        CampaignEventError,
        json.JSONDecodeError,
        LeadStateError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"campaign-coordinator: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
