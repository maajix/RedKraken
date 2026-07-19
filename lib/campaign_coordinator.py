#!/usr/bin/env python3
"""Deterministic campaign state and scheduling boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from harness_config import engagement_yaml, load_engagement
from lead_store import LeadState


class CampaignEventError(ValueError):
    """Raised when a campaign event does not match the public event contract."""


class CampaignCoordinator:
    """Open durable campaign state and describe the next coordinator action."""

    BASELINE_METHODS = (
        "dns",
        "virtual-hosts",
        "services",
        "liveness",
        "redirects",
        "technology",
        "defenses",
        "historical-paths",
        "crawl",
        "content-discovery",
        "client-bundles",
        "api-schema",
    )
    AUTHENTICATED_METHODS = {
        "historical-paths",
        "crawl",
        "content-discovery",
        "client-bundles",
        "api-schema",
    }

    def __init__(self, engagement: Path | str):
        self.engagement = Path(engagement)
        self.store = LeadState(self.engagement)

    @staticmethod
    def _completion(
        decision: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any]:
        reasons = decision["reasons"]
        if reasons == ["converged"]:
            outcome = "converged"
        elif any(reason.endswith("_budget_exhausted") for reason in reasons):
            outcome = "budget_exhausted"
        elif reasons == ["operator_blocked"] and decision["actionable"] == 0:
            outcome = "operator_blocked"
        else:
            outcome = "incomplete"
        return {
            "outcome": outcome,
            "reasons": reasons,
            "actionable": decision["actionable"],
            "remaining_frontier": [
                entry
                for entry in state["coverage"]
                if entry["status"] in {"not-tested", "blocked"}
            ],
        }

    def _coverage_cells(self) -> list[tuple[str, str, str]]:
        try:
            config = load_engagement(engagement_yaml(self.engagement))
        except ValueError:
            return []
        roles = ["anonymous"]
        credentials = config.get("test_credentials") or []
        if isinstance(credentials, list):
            roles.extend(
                f"authorized-role-{number}"
                for number in range(1, len(credentials) + 1)
            )
        cells: list[tuple[str, str, str]] = []
        for target in config.get("targets") or []:
            asset = target.strip().casefold()
            for method in self.BASELINE_METHODS:
                method_roles = roles if method in self.AUTHENTICATED_METHODS else ["anonymous"]
                cells.extend((asset, method, role) for role in method_roles)
        return cells

    @staticmethod
    def _coverage_key(asset: str, method: str, role: str) -> str:
        return f"asset={asset};method={method};role={role}"

    def _discovery_lead(self, asset: str, method: str, role: str) -> dict[str, Any]:
        return {
            "family": "surface-inventory",
            "kind": "discovery",
            "subject": asset,
            "method": method,
            "parameter": role,
            "priority": 100,
            "provenance": ["coordinator:required-coverage"],
            "evidence": [],
            "hypothesis": f"Complete {method} discovery for {asset} as {role}.",
        }

    def _seed_required_coverage(self) -> None:
        state = self.store.snapshot()
        coverage_by_key = {entry["key"]: entry for entry in state["coverage"]}
        leads_by_id = {lead["id"]: lead for lead in state["leads"]}
        for asset, method, role in self._coverage_cells():
            key = self._coverage_key(asset, method, role)
            entry = coverage_by_key.get(key)
            if entry is None:
                entry = self.store.record_coverage(
                    "workflow",
                    key,
                    "not-tested",
                    reason="required discovery pending",
                )["coverage"]
                coverage_by_key[key] = entry
            if entry["status"] != "not-tested":
                continue
            raw = self._discovery_lead(asset, method, role)
            lead_id = self.store.lead_id(raw)
            existing = leads_by_id.get(lead_id)
            if existing is None or existing["status"] not in {"queued", "leased"}:
                ensured = self.store.ensure_lead(raw)["lead"]
                leads_by_id[lead_id] = ensured

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
        self._seed_required_coverage()
        inspection = self.store.inspect()
        completion = self._completion(inspection["can_stop"], inspection["state"])
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
