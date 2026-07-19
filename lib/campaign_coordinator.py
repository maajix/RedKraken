#!/usr/bin/env python3
"""Deterministic campaign state and scheduling boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from chain_store import ChainState, ChainStateError
from harness_config import engagement_yaml, load_engagement, scope_decision
from lead_store import LeadState
from surface_store import SurfaceState


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
    SURFACE_SOURCES = {"recon", "hunter", "bypass", "exploit", "explorer"}
    BYPASS_PROFILES = {
        "edge-waf": ("edge", "waf", "normalization", "cdn"),
        "parser-content-type": ("parser", "content-type", "content_type", "mime", "charset"),
        "auth-routing": ("authentication", "authorization", "routing", "auth", "session"),
        "ratelimit-workflow": (
            "rate-limit",
            "ratelimit",
            "rate_limit",
            "throttling",
            "workflow",
            "workflow-state",
        ),
    }
    SURFACE_METHODS = {
        "host": BASELINE_METHODS,
        "virtual-host": BASELINE_METHODS,
        "asset": BASELINE_METHODS,
        "path": ("crawl", "content-discovery", "parameter-discovery"),
        "endpoint": ("crawl", "content-discovery", "parameter-discovery"),
        "schema": ("api-operations", "api-parameters"),
        "bundle": ("client-bundles", "client-routes"),
        "parameter": ("parameter-characterization",),
        "protocol": ("protocol-enumeration",),
        "technology": ("version-characterization",),
        "version": ("version-characterization",),
        "role": ("authenticated-crawl", "authorization-matrix"),
        "trust-relationship": ("trust-mapping",),
    }

    def __init__(self, engagement: Path | str):
        self.engagement = Path(engagement)
        self.store = LeadState(self.engagement)
        self.surface = SurfaceState(self.engagement)
        self.chain = ChainState(self.engagement)

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

    def _ensure_coverage(
        self,
        asset: str,
        methods: tuple[str, ...],
        role: str,
        *,
        reopen: bool,
        provenance: str,
    ) -> tuple[list[str], list[str]]:
        state = self.store.snapshot()
        coverage_by_key = {entry["key"]: entry for entry in state["coverage"]}
        leads_by_id = {lead["id"]: lead for lead in state["leads"]}
        coverage_ids: list[str] = []
        work_ids: list[str] = []
        for method in methods:
            key = self._coverage_key(asset, method, role)
            entry = coverage_by_key.get(key)
            if entry is None or reopen:
                entry = self.store.record_coverage(
                    "workflow", key, "not-tested", reason="surface discovery pending"
                )["coverage"]
                coverage_by_key[key] = entry
            coverage_ids.append(entry["id"])
            raw = self._discovery_lead(asset, method, role)
            raw["provenance"] = [provenance]
            lead_id = self.store.lead_id(raw)
            existing = leads_by_id.get(lead_id)
            if entry["status"] == "not-tested" and (
                existing is None or existing["status"] not in {"queued", "leased"}
            ):
                existing = self.store.ensure_lead(raw)["lead"]
                leads_by_id[lead_id] = existing
            if existing is not None:
                work_ids.append(existing["id"])
        return coverage_ids, work_ids

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
            raw = self._discovery_lead(asset, method, role)
            lead_id = self.store.lead_id(raw)
            existing = leads_by_id.get(lead_id)
            if entry["status"] != "not-tested":
                if existing is not None and existing["status"] == "queued":
                    outcome = {
                        "tested": "completed",
                        "not-applicable": "completed",
                        "exhausted": "exhausted",
                        "blocked": "blocked",
                    }[entry["status"]]
                    leads_by_id[lead_id] = self.store.close_queued(lead_id, outcome)
                continue
            if existing is None or existing["status"] not in {"queued", "leased"}:
                ensured = self.store.ensure_lead(raw)["lead"]
                leads_by_id[lead_id] = ensured

    @staticmethod
    def _normalized_surface_value(kind: str, value: str) -> str:
        normalized = value.strip()
        if kind in {"host", "virtual-host", "asset"}:
            return normalized.casefold()
        if "://" in normalized:
            parsed = urlsplit(normalized)
            return urlunsplit(
                (
                    parsed.scheme.casefold(),
                    parsed.netloc.casefold(),
                    parsed.path or "/",
                    parsed.query,
                    "",
                )
            )
        return normalized.casefold()

    def _apply_surface(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"source", "observation"}:
            raise CampaignEventError(
                "surface.observed payload must contain source and observation"
            )
        source = payload["source"]
        observation = payload["observation"]
        if source not in self.SURFACE_SOURCES:
            raise CampaignEventError("surface source is unsupported")
        if not isinstance(observation, dict) or set(observation) - {
            "kind",
            "value",
            "parent",
            "attributes",
        }:
            raise CampaignEventError("surface observation fields are invalid")
        kind = observation.get("kind")
        value = observation.get("value")
        parent = observation.get("parent", "")
        attributes = observation.get("attributes", {})
        if kind not in self.SURFACE_METHODS:
            raise CampaignEventError("surface kind is unsupported")
        if not isinstance(value, str) or not value.strip():
            raise CampaignEventError("surface value must be a non-empty string")
        if not isinstance(parent, str) or not isinstance(attributes, dict):
            raise CampaignEventError("surface parent and attributes are invalid")
        config = load_engagement(engagement_yaml(self.engagement))
        scope_subject = parent or value
        if kind in {"parameter", "role", "technology", "version", "trust-relationship"} and not parent:
            return {
                "accepted": False,
                "operator_gate": True,
                "reason": "parent scope is required",
                "result": "rejected",
                "progress": 0,
                "coverage_ids": [],
                "work_ids": [],
            }
        allowed, asset, reason = scope_decision(config, scope_subject)
        if not allowed:
            return {
                "accepted": False,
                "operator_gate": True,
                "reason": reason,
                "result": "rejected",
                "progress": 0,
                "coverage_ids": [],
                "work_ids": [],
            }
        stored = self.surface.observe(
            kind=kind,
            value=self._normalized_surface_value(kind, value),
            parent=self._normalized_surface_value("endpoint", parent) if parent else "",
            attributes=attributes,
            source=source,
        )
        changed = stored["result"] in {"appended", "changed"}
        coverage_ids: list[str] = []
        work_ids: list[str] = []
        if changed:
            role = self._normalized_surface_value("role", value) if kind == "role" else "anonymous"
            coverage_ids, work_ids = self._ensure_coverage(
                asset,
                tuple(self.SURFACE_METHODS[kind]),
                role,
                reopen=stored["result"] == "changed",
                provenance=f"surface:{source}:{stored['observation']['id']}",
            )
            self.store.record_iteration(progress_count=1, surface_delta=1)
        return {
            "accepted": True,
            "operator_gate": False,
            "reason": "in scope",
            "result": stored["result"],
            "progress": 1 if changed else 0,
            "coverage_ids": coverage_ids,
            "work_ids": work_ids,
            "observation_id": stored["observation"]["id"],
        }

    @classmethod
    def _applicable_profile(cls, control: str) -> str | None:
        needle = control.strip().casefold()
        for profile, synonyms in cls.BYPASS_PROFILES.items():
            if needle == profile or needle in synonyms:
                return profile
        return None

    def _apply_resisted(self, payload: Any) -> dict[str, Any]:
        required = {
            "lead_id",
            "control",
            "standard_techniques",
            "positive_control",
            "negative_control",
            "environment_facts",
            "authorized_profiles",
            "safety_requirements",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise CampaignEventError(
                "hypothesis.resisted payload fields do not match the contract"
            )
        lead_id = payload["lead_id"]
        control = payload["control"]
        if not isinstance(lead_id, str) or not lead_id.strip():
            raise CampaignEventError("lead_id must be a non-empty string")
        if not isinstance(control, str) or not control.strip():
            raise CampaignEventError("control must be a non-empty string")
        techniques = self._string_field(payload["standard_techniques"], "standard_techniques")
        if not techniques:
            raise CampaignEventError("standard_techniques must list attempted techniques")
        environment = self._string_field(payload["environment_facts"], "environment_facts")
        safety = self._string_field(payload["safety_requirements"], "safety_requirements")
        authorized = self._string_field(payload["authorized_profiles"], "authorized_profiles")
        unknown = [name for name in authorized if name not in self.BYPASS_PROFILES]
        if unknown:
            raise CampaignEventError(f"unknown bypass profiles: {', '.join(sorted(unknown))}")
        for field in ("positive_control", "negative_control"):
            if not isinstance(payload[field], str) or not payload[field].strip():
                raise CampaignEventError(f"{field} must be a non-empty string")

        state = self.store.snapshot()
        original = next((lead for lead in state["leads"] if lead["id"] == lead_id), None)
        if original is None:
            raise CampaignEventError(f"unknown original lead: {lead_id}")

        config = load_engagement(engagement_yaml(self.engagement))
        allowed, _asset, reason = scope_decision(config, original["subject"])
        if not allowed:
            return {
                "accepted": False,
                "operator_gate": True,
                "reason": reason,
                "control": control,
                "applicable_profiles": [],
                "scheduled": [],
                "rejected": [],
            }

        applicable = self._applicable_profile(control)
        applicable_profiles = [applicable] if applicable is not None else []
        scheduled: list[dict[str, str]] = []
        rejected: list[dict[str, str]] = []
        for profile in applicable_profiles:
            if profile not in authorized:
                rejected.append({"profile": profile, "reason": "unauthorized"})
                continue
            raw = {
                "family": f"bypass-{profile}",
                "kind": "bypass",
                "subject": original["subject"],
                "method": original["method"],
                "parameter": original["parameter"],
                "priority": max(int(original["priority"]), 60),
                "provenance": [
                    "coordinator:bypass",
                    f"profile:{profile}",
                    f"control:{control.strip().casefold()}",
                ],
                "evidence": [
                    f"control:{control.strip()}",
                    *[f"standard:{item}" for item in techniques],
                    f"positive-control:{payload['positive_control'].strip()}",
                    f"negative-control:{payload['negative_control'].strip()}",
                    *[f"environment:{item}" for item in environment],
                ],
                "hypothesis": (
                    f"Attempt {profile} bypass of the {control.strip()} control "
                    f"for {original['subject']}."
                ),
                "parent_leads": [original["id"]],
                "safety_requirements": safety,
            }
            created = self.store.ensure_lead(raw)["lead"]
            scheduled.append({"profile": profile, "lead_id": created["id"]})

        if applicable is None:
            reason = "no bypass profile applies to the observed control"
        elif scheduled:
            reason = "specialist bypass work scheduled"
        else:
            reason = "the applicable profile is not authorized"
        return {
            "accepted": bool(scheduled),
            "operator_gate": bool(applicable_profiles) and not scheduled,
            "reason": reason,
            "control": control,
            "applicable_profiles": applicable_profiles,
            "scheduled": scheduled,
            "rejected": rejected,
        }

    @staticmethod
    def _string_field(value: Any, field: str) -> list[str]:
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            raise CampaignEventError(f"{field} must be an array of non-empty strings")
        return list(dict.fromkeys(item.strip() for item in value))

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
        payload = event["payload"]
        if event["type"] == "surface.observed":
            result = self._apply_surface(payload)
            if result["result"] in {"appended", "changed"}:
                self.chain.mark_material()
            return {"schema_version": 1, "type": event["type"], "result": result}
        if event["type"] == "hypothesis.resisted":
            result = self._apply_resisted(payload)
            if result["scheduled"]:
                self.chain.mark_material()
            return {"schema_version": 1, "type": event["type"], "result": result}
        if event["type"] in {"chain.observe", "chain.certify", "chain.validate"}:
            return {
                "schema_version": 1,
                "type": event["type"],
                "result": self._apply_chain(event["type"], payload),
            }
        if event["type"] != "lead.upsert":
            raise CampaignEventError(f"unsupported event type: {event['type']}")
        if not isinstance(payload, dict) or set(payload) != {"lead"}:
            raise CampaignEventError("lead.upsert payload must contain only lead")
        result = self.store.upsert_lead(payload["lead"])
        self.chain.mark_material()  # A lead revision reopens chain review.
        return {"schema_version": 1, "type": event["type"], "result": result}

    def _apply_chain(self, kind: str, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise CampaignEventError("chain payload must be an object")
        try:
            if kind == "chain.observe":
                if set(payload) != {"node"}:
                    raise CampaignEventError("chain.observe payload must contain only node")
                node = payload["node"]
                if not isinstance(node, dict) or not isinstance(node.get("asset"), str):
                    raise CampaignEventError("chain node asset must be a string")
                config = load_engagement(engagement_yaml(self.engagement))
                allowed, _asset, reason = scope_decision(config, node["asset"])
                if not allowed:
                    return {"accepted": False, "operator_gate": True, "reason": reason}
                observed = self.chain.observe(node)
                return {"accepted": True, "operator_gate": False, **observed}
            if kind == "chain.certify":
                if payload:
                    raise CampaignEventError("chain.certify payload must be empty")
                return {"accepted": True, **self.chain.certify()}
            if set(payload) - {"assignment_id", "severity", "evidence", "title"}:
                raise CampaignEventError("chain.validate payload fields are invalid")
            finding = self.chain.validate(
                payload.get("assignment_id", ""),
                payload.get("severity", "info"),
                payload.get("evidence", []),
                payload.get("title", ""),
            )
            return {"accepted": True, "finding": finding}
        except ChainStateError as exc:
            raise CampaignEventError(str(exc)) from exc

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
            "surface": self.surface.snapshot(),
            "chain": self.chain.snapshot(),
        }
