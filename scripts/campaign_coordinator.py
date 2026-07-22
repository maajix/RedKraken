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
    command.add_argument(
        "--compact",
        action="store_true",
        help="Return only the decision and the material needed to execute it.",
    )
    command.add_argument(
        "--outcome",
        action="store_true",
        help="Read-only terminal outcome and report gate; never advances the campaign.",
    )
    return command


def compact(response: dict[str, object]) -> dict[str, object]:
    action = response.get("next_action")
    kind = action.get("kind") if isinstance(action, dict) else ""
    completion = dict(response.get("completion") or {})
    if kind not in {"report", "report-terminal"}:
        completion.pop("remaining_frontier", None)
    result: dict[str, object] = {
        "schema_version": response.get("schema_version", 1),
        "completion": completion,
        "material_digest": response.get("material_digest"),
        "reporting_permitted": response.get("reporting_permitted", False),
        "next_action": action,
    }
    event = response.get("event")
    if isinstance(event, dict):
        event_result = event.get("result")
        if (
            event.get("type") == "challenge.open"
            and isinstance(event_result, dict)
            and kind == "challenge-lens"
        ):
            event = {
                **event,
                "result": {
                    key: value
                    for key, value in event_result.items()
                    if key != "material"
                },
            }
        result["event"] = event
    return result


def main(argv: list[str]) -> int:
    try:
        args = parser().parse_args(argv[1:])
        if args.outcome and args.event is not None:
            raise ValueError("--outcome is read-only and cannot carry an --event")
        coordinator = CampaignCoordinator(args.engagement)
        if args.outcome:
            response = coordinator.outcome()
        else:
            event = json.loads(args.event) if args.event is not None else None
            response = coordinator.respond(event)
        if args.compact:
            response = compact(response)
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
