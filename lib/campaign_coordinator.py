#!/usr/bin/env python3
"""Deterministic campaign state and scheduling boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from chain_store import ChainState, ChainStateError
from challenge_store import LENSES as CHALLENGE_LENSES, ChallengeState, ChallengeStateError
from finding_store import load_rows as load_findings
from finding_store import normalize as normalize_finding
from finding_store import upsert as upsert_finding
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
    PROHIBITED_IDEAS = (
        "denial-of-service",
        "denial of service",
        "ddos",
        "dos attack",
        "resource exhaustion",
        "destroy",
        "destructive",
        "ransom",
        "wipe production",
        "exfiltrate",
        "drop table",
        "delete all",
        "brick the",
    )

    def __init__(self, engagement: Path | str):
        self.engagement = Path(engagement)
        self.store = LeadState(self.engagement)
        self.surface = SurfaceState(self.engagement)
        self.chain = ChainState(self.engagement)
        self.challenge = ChallengeState(self.engagement)

    def _findings(self) -> list[dict[str, Any]]:
        rows = load_findings(self.engagement / "state" / "findings.jsonl")
        return sorted((normalize_finding(row) for row in rows), key=lambda row: row["id"])

    @staticmethod
    def _finding_view(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Structured, non-secret finding facts used for scheduling and challenge review."""

        fields = (
            "id",
            "title",
            "technique",
            "family",
            "severity",
            "status",
            "summary",
            "description",
            "impact",
            "evidence",
            "endpoint",
            "target_link",
            "method",
            "param",
            "component",
            "file",
            "chain",
        )
        return [
            {field: finding[field] for field in fields if field in finding}
            for finding in findings
        ]

    def _sync_findings(self, findings: list[dict[str, Any]]) -> None:
        """Make recorded findings durable chain-review inputs without duplicate writes."""

        if not findings:
            return
        config = load_engagement(engagement_yaml(self.engagement))
        existing = {
            node["source_id"]: node for node in self.chain.snapshot()["nodes"]
        }
        demonstrated = {"confirmed", "exploited", "exploitable-not-detonated"}
        for finding in findings:
            if finding.get("source") == "campaign-chain":
                continue
            asset = finding.get("endpoint") or finding.get("target_link")
            if not isinstance(asset, str) or not asset.strip():
                continue
            allowed, _asset, _reason = scope_decision(config, asset)
            if not allowed:
                continue
            prior = existing.get(finding["id"])
            metadata = finding.get("chain")
            if not isinstance(metadata, dict):
                metadata = {}
            prior_provides = prior["provides"] if prior else []
            prior_requires = prior["requires"] if prior else []
            prior_safety = prior["safety_requirements"] if prior else []
            node = {
                "source_id": finding["id"],
                "asset": asset.strip(),
                "title": str(finding.get("title") or finding["summary"]).strip(),
                "provides": list(
                    dict.fromkeys([*prior_provides, *metadata.get("provides", [])])
                ),
                "requires": list(
                    dict.fromkeys([*prior_requires, *metadata.get("requires", [])])
                ),
                "severity": finding["severity"],
                "authorized": (prior["authorized"] if prior else True)
                and metadata.get("authorized", True),
                "status": (
                    "demonstrated"
                    if finding["status"] in demonstrated
                    else "observed"
                ),
                "evidence": list(
                    dict.fromkeys(
                        [
                            *finding.get("evidence", []),
                            *(prior["evidence"] if prior else []),
                        ]
                    )
                ),
                "safety_requirements": list(
                    dict.fromkeys(
                        [*prior_safety, *metadata.get("safety_requirements", [])]
                    )
                ),
            }
            if prior is not None and all(prior.get(key) == value for key, value in node.items()):
                continue
            stored = self.chain.observe(node)["node"]
            existing[finding["id"]] = stored

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
        if event["type"] in {
            "chain.observe",
            "chain.certify",
            "chain.validate",
            "chain.reject",
        }:
            return {
                "schema_version": 1,
                "type": event["type"],
                "result": self._apply_chain(event["type"], payload),
            }
        if event["type"] in {"challenge.open", "challenge.submit"}:
            return {
                "schema_version": 1,
                "type": event["type"],
                "result": self._apply_challenge(event["type"], payload),
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
            if kind == "chain.reject":
                if set(payload) != {"assignment_id", "evidence", "reason"}:
                    raise CampaignEventError(
                        "chain.reject payload must contain assignment_id, evidence, and reason"
                    )
                assignment = self.chain.reject(
                    payload.get("assignment_id", ""),
                    payload.get("evidence", []),
                    payload.get("reason", ""),
                )
                return {"accepted": True, "assignment": assignment}
            if set(payload) - {"assignment_id", "severity", "evidence", "title"}:
                raise CampaignEventError("chain.validate payload fields are invalid")
            chain_finding = self.chain.validate(
                payload.get("assignment_id", ""),
                payload.get("severity", "info"),
                payload.get("evidence", []),
                payload.get("title", ""),
            )
            finding = {
                **chain_finding,
                "technique": "Multi-step exploit chain",
                "family": "kill-chain",
                "status": "exploited",
                "summary": chain_finding["title"],
                "component": chain_finding["assignment_id"],
                "source": "campaign-chain",
                "impact": f"Combined path demonstrated: {chain_finding['title']}",
                "remediation": (
                    "Remediate each component and prevent the recorded capability "
                    "from satisfying the downstream prerequisite."
                ),
            }
            stored = upsert_finding(self.engagement, finding)
            return {"accepted": True, "finding": normalize_finding(finding), "stored": stored}
        except ChainStateError as exc:
            raise CampaignEventError(str(exc)) from exc

    @staticmethod
    def _material_view(
        state: dict[str, Any],
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        chain: dict[str, Any],
    ) -> dict[str, Any]:
        """The read-only campaign digest every explorer lens reasons over."""
        return {
            "leads": sorted(
                (
                    {
                        "id": lead["id"],
                        "family": lead["family"],
                        "kind": lead["kind"],
                        "subject": lead["subject"],
                        "method": lead["method"],
                        "parameter": lead["parameter"],
                        "status": lead["status"],
                        "priority": lead["priority"],
                        "hypothesis": lead["hypothesis"],
                        "provenance": lead["provenance"],
                        "evidence": lead["evidence"],
                        "parent_leads": lead["parent_leads"],
                        "parent_findings": lead["parent_findings"],
                        "safety_requirements": lead["safety_requirements"],
                    }
                    for lead in state["leads"]
                ),
                key=lambda entry: entry["id"],
            ),
            "coverage": sorted(
                (
                    {
                        "id": entry["id"],
                        "dimension": entry["dimension"],
                        "key": entry["key"],
                        "status": entry["status"],
                        "reason": entry["reason"],
                    }
                    for entry in state["coverage"]
                ),
                key=lambda entry: entry["key"],
            ),
            "surface": sorted(
                (
                    {
                        "id": item["id"],
                        "kind": item["kind"],
                        "value": item["value"],
                        "parent": item["parent"],
                        "attributes": item["attributes"],
                        "sources": item["sources"],
                    }
                    for item in surface["observations"]
                ),
                key=lambda entry: entry["id"],
            ),
            "findings": CampaignCoordinator._finding_view(findings),
            "chain": {
                "nodes": [
                    {
                        key: node[key]
                        for key in (
                            "source_id",
                            "asset",
                            "title",
                            "provides",
                            "requires",
                            "severity",
                            "authorized",
                            "status",
                            "evidence",
                            "safety_requirements",
                        )
                    }
                    for node in chain["nodes"]
                ],
                "assignments": [
                    {
                        key: assignment.get(key, "")
                        for key in (
                            "id",
                            "provider",
                            "consumer",
                            "token",
                            "status",
                            "severity",
                            "required_evidence",
                            "safety_requirements",
                            "evidence",
                            "reason",
                        )
                    }
                    for assignment in chain["assignments"]
                ],
            },
        }

    @staticmethod
    def _digest(view: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(view, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _material_digest(
        self,
        state: dict[str, Any],
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        chain: dict[str, Any],
    ) -> str:
        return self._digest(self._material_view(state, surface, findings, chain))

    def _apply_challenge(self, kind: str, payload: Any) -> dict[str, Any]:
        try:
            if kind == "challenge.open":
                return self._open_challenge(payload)
            return self._submit_challenge(payload)
        except ChallengeStateError as exc:
            raise CampaignEventError(str(exc)) from exc

    def _open_challenge(self, payload: Any) -> dict[str, Any]:
        if payload not in (None, {}):
            raise CampaignEventError("challenge.open payload must be empty")
        # Bind the round to the same digest respond() reports, after seeding.
        self._seed_required_coverage()
        inspection = self.store.inspect()
        completion = self._completion(inspection["can_stop"], inspection["state"])
        findings = self._findings()
        self._sync_findings(findings)
        if completion["outcome"] != "converged":
            raise CampaignEventError("challenge.open requires converged campaign work")
        if self.chain.snapshot()["review_pending"]:
            raise CampaignEventError("challenge.open requires a certified chain review")
        chain = self.chain.snapshot()
        view = self._material_view(
            inspection["state"], self.surface.snapshot(), findings, chain
        )
        digest = self._digest(view)
        opened = self.challenge.open(digest)
        return {
            "accepted": True,
            "converged": completion["outcome"] == "converged",
            "digest": digest,
            "lenses": list(CHALLENGE_LENSES),
            "status": opened["status"],
            "material": view,
        }

    def _submit_challenge(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"lens", "leads"}:
            raise CampaignEventError("challenge.submit payload must contain lens and leads")
        lens = payload["lens"]
        leads = payload["leads"]
        if lens not in CHALLENGE_LENSES:
            raise CampaignEventError(f"lens must be one of: {', '.join(CHALLENGE_LENSES)}")
        if not isinstance(leads, list):
            raise CampaignEventError("leads must be an array of explorer leads")
        opened = self.challenge.snapshot()
        if opened["status"] != "open":
            raise CampaignEventError("no open convergence challenge to answer")
        digest = opened["digest"]
        inspection = self.store.inspect()
        current_digest = self._material_digest(
            inspection["state"],
            self.surface.snapshot(),
            self._findings(),
            self.chain.snapshot(),
        )
        if current_digest != digest:
            raise CampaignEventError("campaign material changed; open a fresh challenge")
        context = self._gate_context()
        accepted: list[dict[str, str]] = []
        rejected: list[dict[str, str]] = []
        for raw in leads:
            verdict, detail = self._gate_explorer(raw, lens, context)
            if verdict == "accept":
                created = self.store.ensure_lead(detail)["lead"]
                context["leads_by_id"][created["id"]] = created["status"]
                context["accepted_ids"].add(created["id"])
                context["support_tokens"].add(created["id"])
                accepted.append({"subject": detail["subject"], "lead_id": created["id"]})
            else:
                rejected.append(detail)
        if accepted:
            # An accepted unique lead is material campaign work; it reopens review.
            self.chain.mark_material()
        recorded = self.challenge.record(
            lens, digest, [item["lead_id"] for item in accepted], rejected
        )
        return {
            "accepted": accepted,
            "rejected": rejected,
            "reopened": bool(accepted),
            "status": recorded["status"],
            "digest": digest,
        }

    def _gate_context(self) -> dict[str, Any]:
        config = load_engagement(engagement_yaml(self.engagement))
        state = self.store.snapshot()
        leads_by_id = {lead["id"]: lead["status"] for lead in state["leads"]}
        support = set(leads_by_id)
        support.update(entry["key"] for entry in state["coverage"])
        support.update(item["id"] for item in self.surface.snapshot()["observations"])
        support.update(finding["id"] for finding in self._findings())
        return {
            "config": config,
            "leads_by_id": leads_by_id,
            "support_tokens": support,
            "accepted_ids": set(),
        }

    def _gate_explorer(
        self, raw: Any, lens: str, context: dict[str, Any]
    ) -> tuple[str, dict[str, str]]:
        """Quality-gate one explorer lead; reasons never count as progress."""
        allowed_keys = {
            "subject",
            "hypothesis",
            "observation",
            "next_test",
            "provenance",
            "priority",
            "safety_requirements",
            "family",
            "kind",
            "method",
            "parameter",
        }
        subject = raw.get("subject") if isinstance(raw, dict) else None
        label = subject.strip() if isinstance(subject, str) else ""

        def reject(reason: str) -> tuple[str, dict[str, str]]:
            return "reject", {"subject": label, "reason": reason}

        if not isinstance(raw, dict) or set(raw) - allowed_keys:
            return reject("incomplete")
        for field in ("subject", "hypothesis", "observation", "next_test", "family", "kind"):
            if not isinstance(raw.get(field), str) or not raw[field].strip():
                return reject("incomplete")
        provenance = raw.get("provenance")
        if (
            not isinstance(provenance, list)
            or not provenance
            or not all(isinstance(item, str) and item.strip() for item in provenance)
        ):
            return reject("incomplete")
        priority = raw.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
            return reject("incomplete")
        safety = raw.get("safety_requirements")
        if (
            not isinstance(safety, list)
            or not safety
            or not all(isinstance(item, str) and item.strip() for item in safety)
        ):
            return reject("incomplete")
        method = raw.get("method", "GET")
        parameter = raw.get("parameter", "")
        if not isinstance(method, str) or not isinstance(parameter, str):
            return reject("incomplete")

        haystack = " ".join(
            (raw["subject"], raw["hypothesis"], raw["next_test"], raw["family"], raw["kind"])
        ).casefold()
        if any(token in haystack for token in self.PROHIBITED_IDEAS):
            return reject("prohibited")

        allowed, _asset, _reason = scope_decision(context["config"], raw["subject"].strip())
        if not allowed:
            return reject("out-of-scope")

        tokens = {item.strip() for item in provenance}
        if tokens.isdisjoint(context["support_tokens"]):
            return reject("unsupported")

        identity = {
            "family": raw["family"],
            "kind": raw["kind"],
            "subject": raw["subject"],
            "method": method,
            "parameter": parameter,
        }
        lead_id = LeadState.lead_id(identity)
        if lead_id in context["accepted_ids"]:
            return reject("duplicate")
        existing = context["leads_by_id"].get(lead_id)
        if existing in {"queued", "leased"}:
            return reject("duplicate")
        if existing in {"completed", "exhausted", "blocked"}:
            return reject("already-tested")

        lead_raw = {
            **identity,
            "priority": priority,
            "provenance": [*(item.strip() for item in provenance), f"challenge:{lens}"],
            "evidence": [
                f"observation:{raw['observation'].strip()}",
                f"next-test:{raw['next_test'].strip()}",
            ],
            "hypothesis": raw["hypothesis"].strip(),
            "safety_requirements": [item.strip() for item in safety],
        }
        return "accept", lead_raw

    def _next_action(
        self,
        completion: dict[str, Any],
        state: dict[str, Any],
        next_work: dict[str, Any] | None,
        findings: list[dict[str, Any]],
        chain_snapshot: dict[str, Any],
        challenge_snapshot: dict[str, Any],
        material_digest: str,
        material: dict[str, Any],
        reporting_permitted: bool,
    ) -> dict[str, Any]:
        """Return one deterministic action so the model never invents phase order."""

        outcome = completion["outcome"]
        if reporting_permitted:
            return {
                "kind": "report" if outcome == "converged" else "report-terminal",
                "reason": outcome,
            }

        leased = sorted(
            (
                {
                    "lead_id": lead["id"],
                    "worker_id": lead["lease_owner"],
                    "lease_until": lead["lease_until"],
                }
                for lead in state["leads"]
                if lead["status"] == "leased"
            ),
            key=lambda lease: lease["lead_id"],
        )
        if leased:
            return {
                "kind": "await-leases",
                "leases": leased,
                "reason": "dispatched work is still durably leased",
            }

        candidates = sorted(
            (
                assignment
                for assignment in chain_snapshot["assignments"]
                if assignment["status"] == "candidate"
            ),
            key=lambda assignment: assignment["id"],
        )
        if candidates:
            return {
                "kind": "validate-chain",
                "agent": "exploit-agent",
                "assignment": candidates[0],
                "result_events": ["chain.validate", "chain.reject"],
                "reason": "a demonstrated capability satisfies an untested prerequisite",
            }

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        confirmed = sorted(
            (
                finding
                for finding in findings
                if finding["status"] == "confirmed"
                and (finding.get("endpoint") or finding.get("target_link"))
                and finding.get("source") != "campaign-chain"
            ),
            key=lambda finding: (
                severity_order[finding["severity"]],
                finding["id"],
            ),
        )
        if confirmed:
            return {
                "kind": "exploit-finding",
                "agent": "exploit-agent",
                "finding_id": confirmed[0]["id"],
                "finding": self._finding_view([confirmed[0]])[0],
                "reason": "confirmed live finding has not reached a terminal impact status",
            }

        if next_work is not None:
            if next_work["kind"] == "discovery" or next_work["family"] == "surface-inventory":
                agent = "recon-agent"
            elif next_work["kind"] == "bypass":
                agent = "bypass-specialist"
            else:
                agent = "web-vuln-hunter"
            return {
                "kind": "dispatch-lead",
                "agent": agent,
                "lead_id": next_work["id"],
                "lead": next_work,
                "worker_id": f"campaign-{next_work['id']}",
                "lease_required": agent != "recon-agent",
                "reason": "highest-priority eligible durable lead",
            }

        if chain_snapshot["review_pending"]:
            return {
                "kind": "review-chain",
                "finding_ids": [finding["id"] for finding in findings],
                "findings": self._finding_view(findings),
                "chain": chain_snapshot,
                "result_events": ["chain.observe", "chain.certify"],
                "reason": "material campaign state changed since the last chain review",
            }

        if outcome == "converged":
            if (
                challenge_snapshot["status"] == "open"
                and challenge_snapshot["digest"] == material_digest
            ):
                pending = [
                    lens
                    for lens in CHALLENGE_LENSES
                    if challenge_snapshot["lenses"].get(lens) == "pending"
                ]
                if pending:
                    return {
                        "kind": "challenge-lens",
                        "agent": pending[0],
                        "lens": pending[0],
                        "digest": material_digest,
                        "material": material,
                        "reason": "independent convergence lens is pending",
                    }
            return {
                "kind": "open-challenge",
                "event": {
                    "schema_version": 1,
                    "type": "challenge.open",
                    "payload": {},
                },
                "reason": "coverage converged but the current digest is not challenge-certified",
            }

        return {
            "kind": "operator-input",
            "reason": ",".join(completion["reasons"]),
        }

    def _reporting_permitted(
        self,
        completion: dict[str, Any],
        state: dict[str, Any],
        chain_snapshot: dict[str, Any],
        challenge_snapshot: dict[str, Any],
        material_digest: str,
    ) -> bool:
        """The single terminal gate: coverage, work, leases, bypass, chain, and
        challenge are all terminal for the *current* material digest."""
        if any(lead["status"] == "leased" for lead in state["leads"]):
            return False
        if completion["outcome"] in {"budget_exhausted", "operator_blocked"}:
            return True
        return (
            completion["outcome"] == "converged"
            and not chain_snapshot["review_pending"]
            and challenge_snapshot["status"] == "certified"
            and challenge_snapshot["digest"] == material_digest
        )

    def outcome(self) -> dict[str, Any]:
        """Read-only terminal outcome for the report gate; never seeds or mutates
        campaign scheduling state, so a report render cannot advance the campaign."""
        inspection = self.store.inspect()
        completion = self._completion(inspection["can_stop"], inspection["state"])
        next_work = (
            inspection["next_work"]
            if completion["outcome"] == "incomplete"
            else None
        )
        surface_snapshot = self.surface.snapshot()
        chain_snapshot = self.chain.snapshot()
        challenge_snapshot = self.challenge.snapshot()
        findings = self._findings()
        material = self._material_view(
            inspection["state"], surface_snapshot, findings, chain_snapshot
        )
        material_digest = self._digest(material)
        reporting_permitted = self._reporting_permitted(
            completion,
            inspection["state"],
            chain_snapshot,
            challenge_snapshot,
            material_digest,
        )
        return {
            "completion": completion,
            "findings": self._finding_view(findings),
            "chain": chain_snapshot,
            "challenge": challenge_snapshot,
            "material_digest": material_digest,
            "reporting_permitted": reporting_permitted,
            "next_action": self._next_action(
                completion,
                inspection["state"],
                next_work,
                findings,
                chain_snapshot,
                challenge_snapshot,
                material_digest,
                material,
                reporting_permitted,
            ),
        }

    def respond(self, event: Any = None) -> dict[str, Any]:
        findings = self._findings()
        self._sync_findings(findings)
        event_result = self._apply(event) if event is not None else None
        self._seed_required_coverage()
        inspection = self.store.inspect()
        completion = self._completion(inspection["can_stop"], inspection["state"])
        next_work = (
            inspection["next_work"]
            if completion["outcome"] == "incomplete"
            else None
        )
        surface_snapshot = self.surface.snapshot()
        chain_snapshot = self.chain.snapshot()
        challenge_snapshot = self.challenge.snapshot()
        findings = self._findings()
        material = self._material_view(
            inspection["state"], surface_snapshot, findings, chain_snapshot
        )
        material_digest = self._digest(material)
        reporting_permitted = self._reporting_permitted(
            completion,
            inspection["state"],
            chain_snapshot,
            challenge_snapshot,
            material_digest,
        )
        return {
            "schema_version": 1,
            "event": event_result,
            "state": inspection["state"],
            "next_work": next_work,
            "completion": completion,
            "surface": surface_snapshot,
            "findings": self._finding_view(findings),
            "chain": chain_snapshot,
            "challenge": challenge_snapshot,
            "material_digest": material_digest,
            "reporting_permitted": reporting_permitted,
            "next_action": self._next_action(
                completion,
                inspection["state"],
                next_work,
                findings,
                chain_snapshot,
                challenge_snapshot,
                material_digest,
                material,
                reporting_permitted,
            ),
        }
