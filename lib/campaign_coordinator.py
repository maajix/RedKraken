#!/usr/bin/env python3
"""Deterministic campaign state and scheduling boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lead_store import LeadState


class CampaignEventError(ValueError):
    """Raised when a campaign event does not match the public event contract."""


class CampaignCoordinator:
    """Open durable campaign state and describe the next coordinator action."""

    def __init__(self, engagement: Path | str):
        self.store = LeadState(engagement)

    @staticmethod
    def _completion(decision: dict[str, Any]) -> dict[str, Any]:
        reasons = decision["reasons"]
        if reasons == ["converged"]:
            outcome = "converged"
        elif any(reason.endswith("_budget_exhausted") for reason in reasons):
            outcome = "budget_exhausted"
        else:
            outcome = "incomplete"
        return {
            "outcome": outcome,
            "reasons": reasons,
            "actionable": decision["actionable"],
        }

    def _apply(self, event: Any) -> dict[str, Any]:
        if not isinstance(event, dict) or set(event) != {
            "schema_version",
            "type",
            "payload",
        }:
            raise CampaignEventError(
                "event must contain only schema_version, type, and payload"
            )
        if event["schema_version"] != 1:
            raise CampaignEventError("event schema_version must be 1")
        if event["type"] != "lead.upsert":
            raise CampaignEventError(f"unsupported event type: {event['type']}")
        payload = event["payload"]
        if not isinstance(payload, dict) or set(payload) != {"lead"}:
            raise CampaignEventError("lead.upsert payload must contain only lead")
        return {
            "schema_version": 1,
            "type": event["type"],
            "result": self.store.upsert_lead(payload["lead"]),
        }

    def respond(self, event: Any = None) -> dict[str, Any]:
        event_result = self._apply(event) if event is not None else None
        inspection = self.store.inspect()
        completion = self._completion(inspection["can_stop"])
        next_work = (
            inspection["next_work"]
            if completion["outcome"] == "incomplete"
            else None
        )
        return {
            "schema_version": 1,
            "event": event_result,
            "state": inspection["state"],
            "next_work": next_work,
            "completion": completion,
        }
