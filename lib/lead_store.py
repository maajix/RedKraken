#!/usr/bin/env python3
"""Atomic lead, coverage, and convergence state behind one small interface."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


class LeadStateError(ValueError):
    """Raised when state or an operation violates the module interface."""


def _ordered_union(left: list[str], right: list[str]) -> list[str]:
    return list(dict.fromkeys([*left, *right]))


class LeadState:
    """Own validated durable lead state; callers need not coordinate file I/O."""

    def __init__(self, directory: Path | str, clock: Callable[[], str] | None = None):
        self.directory = Path(directory)
        self.state_dir = self.directory / "state"
        self.path = self.state_dir / "lead-state.json"
        self.lock_path = self.state_dir / ".lead-state.lock"
        self.clock = clock

    def _now(self) -> str:
        if self.clock is not None:
            value = self.clock()
            self._parse_time(value)
            return value
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise LeadStateError("clock must return an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise LeadStateError("clock timestamp must include a timezone")
        return parsed

    @staticmethod
    def _identity(raw: dict[str, Any]) -> dict[str, str]:
        required = ("family", "kind", "subject")
        for field in required:
            if not isinstance(raw.get(field), str) or not raw[field].strip():
                raise LeadStateError(f"{field} must be a non-empty string")
        return {
            "family": raw["family"].strip().casefold(),
            "kind": raw["kind"].strip().casefold(),
            "subject": raw["subject"].strip(),
            "method": str(raw.get("method", "GET")).strip().upper(),
            "parameter": str(raw.get("parameter", "")).strip().casefold(),
        }

    @classmethod
    def _normalize_lead(cls, raw: Any, *, persisted: bool = False) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise LeadStateError("lead must be an object")
        input_fields = {
            "family",
            "kind",
            "subject",
            "method",
            "parameter",
            "priority",
            "provenance",
            "evidence",
            "hypothesis",
            "parent_leads",
            "parent_findings",
            "safety_requirements",
        }
        if not persisted and set(raw) - input_fields:
            raise LeadStateError(
                f"unsupported lead fields: {', '.join(sorted(set(raw) - input_fields))}"
            )
        identity = cls._identity(raw)
        fingerprint = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        priority = raw.get("priority", 50)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
            raise LeadStateError("priority must be an integer from 0 through 100")
        hypothesis = raw.get("hypothesis", "")
        if not isinstance(hypothesis, str):
            raise LeadStateError("hypothesis must be a string")
        parent_leads = cls._string_list(raw.get("parent_leads", []), "parent_leads")
        if any(not re.fullmatch(r"L-[a-f0-9]{16}", item) for item in parent_leads):
            raise LeadStateError("parent_leads must contain stable lead ids")
        parent_findings = cls._string_list(raw.get("parent_findings", []), "parent_findings")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item) for item in parent_findings):
            raise LeadStateError("parent_findings must contain finding ids")
        lead = {
            "id": f"L-{fingerprint[:16]}",
            "fingerprint": fingerprint,
            **identity,
            "priority": priority,
            "status": "queued",
            "attempts": 0,
            "provenance": cls._string_list(raw.get("provenance", []), "provenance"),
            "evidence": cls._string_list(raw.get("evidence", []), "evidence"),
            "hypothesis": hypothesis.strip(),
            "parent_leads": parent_leads,
            "parent_findings": parent_findings,
            "safety_requirements": cls._string_list(
                raw.get("safety_requirements", []), "safety_requirements"
            ),
        }
        return lead

    @staticmethod
    def _string_list(value: Any, field: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            raise LeadStateError(f"{field} must be an array of non-empty strings")
        return list(dict.fromkeys(item.strip() for item in value))

    def _empty(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "revision": 0,
            "leads": [],
            "coverage": [],
            "loop": {
                "iterations": 0,
                "max_iterations": 25,
                "no_progress_rounds": 0,
                "max_no_progress_rounds": 3,
                "max_attempts": 3,
                "requests": 0,
                "max_requests": 10000,
                "max_seconds": 315360000,
                "started_at": self._now(),
                "progress_count": 0,
                "surface_delta": 0,
            },
        }

    def _prepare(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LeadStateError(f"lead state is invalid JSON: {exc}") from exc
        self._validate_state(state)
        return state

    @classmethod
    def _validate_state(cls, state: Any) -> None:
        def invalid(message: str) -> None:
            raise LeadStateError(f"state schema: {message}")

        top_keys = {"schema_version", "revision", "leads", "coverage", "loop"}
        if not isinstance(state, dict) or set(state) != top_keys:
            invalid("top-level fields do not match lead-state-v1")
        if state["schema_version"] != 1:
            invalid("schema_version must be 1")
        if isinstance(state["revision"], bool) or not isinstance(state["revision"], int) or state["revision"] < 0:
            invalid("revision must be a non-negative integer")
        if not isinstance(state["leads"], list) or not isinstance(state["coverage"], list):
            invalid("leads and coverage must be arrays")

        loop_keys = {
            "iterations",
            "max_iterations",
            "no_progress_rounds",
            "max_no_progress_rounds",
            "max_attempts",
            "requests",
            "max_requests",
            "max_seconds",
            "started_at",
            "progress_count",
            "surface_delta",
        }
        loop = state["loop"]
        if not isinstance(loop, dict) or set(loop) != loop_keys:
            invalid("loop fields do not match lead-state-v1")
        for field in ("iterations", "no_progress_rounds", "requests", "progress_count", "surface_delta"):
            if isinstance(loop[field], bool) or not isinstance(loop[field], int) or loop[field] < 0:
                invalid(f"loop.{field} must be a non-negative integer")
        for field in (
            "max_iterations",
            "max_no_progress_rounds",
            "max_attempts",
            "max_requests",
            "max_seconds",
        ):
            if isinstance(loop[field], bool) or not isinstance(loop[field], int) or loop[field] < 1:
                invalid(f"loop.{field} must be a positive integer")
        cls._parse_time(loop["started_at"])

        lead_ids: set[str] = set()
        fingerprints: set[str] = set()
        required_lead = {
            "id",
            "fingerprint",
            "family",
            "kind",
            "subject",
            "method",
            "parameter",
            "priority",
            "status",
            "attempts",
            "provenance",
            "evidence",
            "created_at",
            "updated_at",
            "hypothesis",
            "parent_leads",
            "parent_findings",
            "safety_requirements",
        }
        for lead in state["leads"]:
            if not isinstance(lead, dict) or not required_lead <= set(lead) or set(lead) - (required_lead | {"lease_owner", "lease_until"}):
                invalid("lead fields do not match lead-v1")
            try:
                normalized = cls._normalize_lead(lead, persisted=True)
            except LeadStateError as exc:
                invalid(str(exc))
            if lead["id"] != normalized["id"] or lead["fingerprint"] != normalized["fingerprint"]:
                invalid("lead identity does not match its fingerprint")
            if lead["id"] in lead_ids or lead["fingerprint"] in fingerprints:
                invalid("lead ids and fingerprints must be unique")
            lead_ids.add(lead["id"])
            fingerprints.add(lead["fingerprint"])
            if lead["status"] not in {"queued", "leased", "completed", "exhausted", "blocked"}:
                invalid("lead status is invalid")
            if isinstance(lead["attempts"], bool) or not isinstance(lead["attempts"], int) or lead["attempts"] < 0:
                invalid("lead attempts must be a non-negative integer")
            for field in ("created_at", "updated_at"):
                cls._parse_time(lead[field])
            if lead["status"] == "leased":
                if not isinstance(lead.get("lease_owner"), str) or not lead["lease_owner"]:
                    invalid("leased lead requires lease_owner")
                cls._parse_time(lead.get("lease_until"))
            elif "lease_owner" in lead or "lease_until" in lead:
                invalid("only leased leads may carry lease fields")

        coverage_ids: set[str] = set()
        coverage_keys = {"id", "dimension", "key", "status", "reason", "created_at", "updated_at"}
        for entry in state["coverage"]:
            if not isinstance(entry, dict) or set(entry) != coverage_keys:
                invalid("coverage fields do not match coverage-v1")
            if entry["dimension"] not in {"endpoint", "workflow", "family", "scenario"}:
                invalid("coverage dimension is invalid")
            if not isinstance(entry["key"], str) or not entry["key"]:
                invalid("coverage key must be non-empty")
            expected = hashlib.sha256(f"{entry['dimension']}\0{entry['key']}".encode()).hexdigest()
            if entry["id"] != f"C-{expected[:16]}" or entry["id"] in coverage_ids:
                invalid("coverage id is invalid or duplicated")
            coverage_ids.add(entry["id"])
            if entry["status"] not in {"tested", "exhausted", "blocked", "not-applicable", "not-tested"}:
                invalid("coverage status is invalid")
            if not isinstance(entry["reason"], str):
                invalid("coverage reason must be a string")
            if entry["status"] in {"blocked", "not-tested"} and not entry["reason"].strip():
                invalid("blocked and not-tested coverage require a reason")
            if entry["dimension"] == "scenario" and not cls._versioned_scenario(entry["key"]):
                invalid("scenario coverage requires a versioned WSTG or ASVS key")
            cls._parse_time(entry["created_at"])
            cls._parse_time(entry["updated_at"])

    def _write(self, state: dict[str, Any]) -> None:
        state["revision"] = state.get("revision", 0) + 1
        self._validate_state(state)
        fd, temp_name = tempfile.mkstemp(prefix=".lead-state.", dir=self.state_dir, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _mutate(self, operation: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._load()
            result = operation(state)
            self._write(state)
            return copy.deepcopy(result)

    def upsert_lead(self, raw: Any) -> dict[str, Any]:
        return self._upsert_lead(raw, requeue_terminal=False)

    @classmethod
    def lead_id(cls, raw: Any) -> str:
        """Return the stable id an input lead would receive without writing state."""
        return str(cls._normalize_lead(raw)["id"])

    def ensure_lead(self, raw: Any) -> dict[str, Any]:
        """Upsert a lead and requeue it when required work became pending again."""
        return self._upsert_lead(raw, requeue_terminal=True)

    def _upsert_lead(
        self, raw: Any, *, requeue_terminal: bool
    ) -> dict[str, Any]:
        incoming = self._normalize_lead(raw)
        timestamp = self._now()

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            for lead in state["leads"]:
                if lead["fingerprint"] != incoming["fingerprint"]:
                    continue
                lead["priority"] = max(lead["priority"], incoming["priority"])
                lead["provenance"] = _ordered_union(lead["provenance"], incoming["provenance"])
                lead["evidence"] = _ordered_union(lead["evidence"], incoming["evidence"])
                lead["parent_leads"] = _ordered_union(
                    lead["parent_leads"], incoming["parent_leads"]
                )
                lead["parent_findings"] = _ordered_union(
                    lead["parent_findings"], incoming["parent_findings"]
                )
                lead["safety_requirements"] = _ordered_union(
                    lead["safety_requirements"], incoming["safety_requirements"]
                )
                if incoming["hypothesis"]:
                    lead["hypothesis"] = incoming["hypothesis"]
                if requeue_terminal and lead["status"] in {
                    "completed",
                    "exhausted",
                    "blocked",
                }:
                    lead["status"] = "queued"
                    lead["attempts"] = 0
                lead["updated_at"] = timestamp
                return {
                    "result": "requeued" if lead["status"] == "queued" and requeue_terminal else "updated",
                    "lead": lead,
                }
            incoming["created_at"] = timestamp
            incoming["updated_at"] = timestamp
            state["leads"].append(incoming)
            return {"result": "appended", "lead": incoming}

        return self._mutate(operation)

    def snapshot(self) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            return copy.deepcopy(self._load())

    @staticmethod
    def _next_eligible(state: dict[str, Any]) -> dict[str, Any] | None:
        max_attempts = state["loop"]["max_attempts"]
        candidates = [
            lead
            for lead in state["leads"]
            if lead["status"] == "queued" and lead["attempts"] < max_attempts
        ]
        if not candidates:
            return None
        terminal_baseline: dict[str, int] = {}
        for lead in state["leads"]:
            if (
                lead["kind"] == "discovery"
                and "coordinator:required-coverage" in lead["provenance"]
                and lead["status"] in {"completed", "exhausted", "blocked"}
            ):
                terminal_baseline[lead["subject"]] = (
                    terminal_baseline.get(lead["subject"], 0) + 1
                )

        def scheduling_key(lead: dict[str, Any]) -> tuple[int, int, int, str]:
            baseline = (
                lead["kind"] == "discovery"
                and "coordinator:required-coverage" in lead["provenance"]
            )
            if baseline:
                lane = 0
            elif lead["kind"] == "discovery":
                lane = 1
            else:
                lane = 2
            served = terminal_baseline.get(lead["subject"], 0) if baseline else 0
            return lane, served, -lead["priority"], lead["id"]

        return sorted(candidates, key=scheduling_key)[0]

    @staticmethod
    def _pending_bypass(state: dict[str, Any], lead_id: str) -> list[dict[str, Any]]:
        """Return non-terminal bypass leads that escalated the given hypothesis."""
        return [
            child
            for child in state["leads"]
            if child["kind"] == "bypass"
            and lead_id in child["parent_leads"]
            and child["status"] in {"queued", "leased"}
        ]

    @staticmethod
    def _has_bypass_children(state: dict[str, Any], lead_id: str) -> bool:
        return any(
            child["kind"] == "bypass" and lead_id in child["parent_leads"]
            for child in state["leads"]
        )

    def close_queued(self, lead_id: str, outcome: str) -> dict[str, Any]:
        """Close scheduler work whose coverage became terminal before leasing."""
        if outcome not in {"completed", "exhausted", "blocked"}:
            raise LeadStateError("outcome must be completed, exhausted, or blocked")
        timestamp = self._now()

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            lead = next((item for item in state["leads"] if item["id"] == lead_id), None)
            if lead is None:
                raise LeadStateError(f"unknown lead id: {lead_id}")
            if lead["status"] == "queued":
                lead["status"] = outcome
                lead["updated_at"] = timestamp
            return lead

        return self._mutate(operation)

    def inspect(self) -> dict[str, Any]:
        """Initialize if needed, then return one consistent read-only campaign view."""
        self._prepare()
        current = self._parse_time(self._now())
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            missing = not self.path.exists()
            state = self._load()
            before_recovery = copy.deepcopy(state)
            self._recover_stale(state, current)
            if missing or state != before_recovery:
                self._write(state)
            return {
                "state": copy.deepcopy(state),
                "next_work": copy.deepcopy(self._next_eligible(state)),
                "can_stop": copy.deepcopy(self._can_stop(state, current)),
            }

    @staticmethod
    def _worker(value: Any) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 128:
            raise LeadStateError("worker must be a non-empty string of at most 128 characters")
        return value.strip()

    def _recover_stale(self, state: dict[str, Any], current: datetime) -> None:
        max_attempts = state["loop"]["max_attempts"]
        for lead in state["leads"]:
            if lead.get("status") != "leased":
                continue
            lease_until = self._parse_time(lead["lease_until"])
            if lease_until > current:
                continue
            lead.pop("lease_owner", None)
            lead.pop("lease_until", None)
            reached_cap = lead["attempts"] >= max_attempts
            if reached_cap and self._pending_bypass(state, lead["id"]):
                # A hypothesis cannot exhaust while its specialist work remains.
                lead["status"] = "queued"
            else:
                lead["status"] = "exhausted" if reached_cap else "queued"
            lead["updated_at"] = current.isoformat().replace("+00:00", "Z")

    def _lease(
        self,
        worker: str,
        lease_seconds: int,
        lead_id: str | None,
    ) -> dict[str, Any] | None:
        owner = self._worker(worker)
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 86400:
            raise LeadStateError("lease_seconds must be an integer from 1 through 86400")
        timestamp = self._now()
        current = self._parse_time(timestamp)
        lease_until = (current + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")

        def operation(state: dict[str, Any]) -> dict[str, Any] | None:
            self._recover_stale(state, current)
            max_attempts = state["loop"]["max_attempts"]
            if lead_id is None:
                lead = self._next_eligible(state)
                if lead is None:
                    return None
            else:
                lead = next(
                    (item for item in state["leads"] if item["id"] == lead_id), None
                )
                if lead is None:
                    raise LeadStateError(f"unknown lead id: {lead_id}")
                if lead["status"] == "leased" and lead.get("lease_owner") == owner:
                    return lead
                if lead["status"] != "queued" or lead["attempts"] >= max_attempts:
                    raise LeadStateError(f"lead is not available to lease: {lead_id}")
            lead["status"] = "leased"
            lead["attempts"] += 1
            lead["lease_owner"] = owner
            lead["lease_until"] = lease_until
            lead["updated_at"] = timestamp
            return lead

        return self._mutate(operation)

    def lease_next(self, worker: str, lease_seconds: int = 300) -> dict[str, Any] | None:
        return self._lease(worker, lease_seconds, None)

    def lease_lead(
        self, lead_id: str, worker: str, lease_seconds: int = 300
    ) -> dict[str, Any]:
        leased = self._lease(worker, lease_seconds, lead_id)
        if leased is None:  # Targeted leasing either returns the lead or raises.
            raise LeadStateError(f"lead is not available to lease: {lead_id}")
        return leased

    def release_lead(self, lead_id: str, worker: str) -> dict[str, Any]:
        owner = self._worker(worker)
        timestamp = self._now()

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            lead = next((item for item in state["leads"] if item["id"] == lead_id), None)
            if lead is None:
                raise LeadStateError(f"unknown lead id: {lead_id}")
            if lead.get("status") != "leased" or lead.get("lease_owner") != owner:
                raise LeadStateError("lead must be held by the lease owner")
            lead["status"] = "queued"
            lead["attempts"] = max(0, lead["attempts"] - 1)
            lead.pop("lease_owner", None)
            lead.pop("lease_until", None)
            lead["updated_at"] = timestamp
            return lead

        return self._mutate(operation)

    def complete_lead(
        self,
        lead_id: str,
        worker: str,
        outcome: str,
        evidence: list[str] | None = None,
    ) -> dict[str, Any]:
        owner = self._worker(worker)
        if outcome not in {"completed", "exhausted", "blocked"}:
            raise LeadStateError("outcome must be completed, exhausted, or blocked")
        merged_evidence = self._string_list(evidence or [], "evidence")
        timestamp = self._now()

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            lead = next((item for item in state["leads"] if item["id"] == lead_id), None)
            if lead is None:
                raise LeadStateError(f"unknown lead id: {lead_id}")
            if lead.get("status") != "leased" or lead.get("lease_owner") != owner:
                raise LeadStateError("lead must be held by the lease owner")
            final_evidence = merged_evidence
            if outcome == "exhausted":
                if self._pending_bypass(state, lead_id):
                    raise LeadStateError(
                        "hypothesis cannot be exhausted while specialist bypass work remains"
                    )
                if self._has_bypass_children(state, lead_id):
                    final_evidence = _ordered_union(
                        merged_evidence, ["not bypassed under the tested matrix"]
                    )
            lead["status"] = outcome
            lead["evidence"] = _ordered_union(lead["evidence"], final_evidence)
            lead.pop("lease_owner", None)
            lead.pop("lease_until", None)
            lead["updated_at"] = timestamp
            return lead

        return self._mutate(operation)

    def record_coverage(
        self,
        dimension: str,
        key: str,
        status: str,
        reason: str = "",
    ) -> dict[str, Any]:
        dimensions = {"endpoint", "workflow", "family", "scenario"}
        statuses = {"tested", "exhausted", "blocked", "not-applicable", "not-tested"}
        if dimension not in dimensions:
            raise LeadStateError(f"coverage dimension must be one of: {', '.join(sorted(dimensions))}")
        if not isinstance(key, str) or not key.strip():
            raise LeadStateError("coverage key must be a non-empty string")
        if status not in statuses:
            raise LeadStateError(f"coverage status must be one of: {', '.join(sorted(statuses))}")
        if not isinstance(reason, str):
            raise LeadStateError("coverage reason must be a string")
        normalized_key = key.strip()
        if status in {"blocked", "not-tested"} and not reason.strip():
            raise LeadStateError("blocked and not-tested coverage require a non-empty reason")
        if dimension == "scenario" and not self._versioned_scenario(normalized_key):
            raise LeadStateError("scenario coverage requires a versioned WSTG or ASVS key")
        fingerprint = hashlib.sha256(f"{dimension}\0{normalized_key}".encode()).hexdigest()
        timestamp = self._now()

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            entry = next((item for item in state["coverage"] if item["id"] == f"C-{fingerprint[:16]}"), None)
            result = "updated"
            if entry is None:
                entry = {
                    "id": f"C-{fingerprint[:16]}",
                    "dimension": dimension,
                    "key": normalized_key,
                    "created_at": timestamp,
                }
                state["coverage"].append(entry)
                result = "appended"
            entry["status"] = status
            entry["reason"] = reason.strip()
            entry["updated_at"] = timestamp
            return {"result": result, "coverage": entry}

        return self._mutate(operation)

    @staticmethod
    def _versioned_scenario(key: str) -> bool:
        return bool(
            re.fullmatch(r"WSTG-v42-[A-Z]{4}-[0-9]{2}", key)
            or re.fullmatch(r"v5\.0\.0-[0-9]+\.[0-9]+\.[0-9]+", key)
        )

    def configure_loop(self, **limits: int) -> dict[str, Any]:
        allowed = {
            "max_iterations",
            "max_no_progress_rounds",
            "max_attempts",
            "max_requests",
            "max_seconds",
        }
        if not limits or set(limits) - allowed:
            raise LeadStateError(f"loop limits must use: {', '.join(sorted(allowed))}")
        for name, value in limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise LeadStateError(f"{name} must be a positive integer")

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            state["loop"].update(limits)
            return state["loop"]

        return self._mutate(operation)

    @classmethod
    def _can_stop(cls, state: dict[str, Any], current: datetime) -> dict[str, Any]:
        loop = state["loop"]
        actionable = sum(lead["status"] in {"queued", "leased"} for lead in state["leads"])
        budget_reasons: list[str] = []
        if loop["iterations"] >= loop["max_iterations"]:
            budget_reasons.append("iteration_budget_exhausted")
        if loop["no_progress_rounds"] >= loop["max_no_progress_rounds"]:
            budget_reasons.append("no_progress_budget_exhausted")
        if loop["requests"] >= loop["max_requests"]:
            budget_reasons.append("request_budget_exhausted")
        started = cls._parse_time(loop["started_at"])
        if max(0.0, (current - started).total_seconds()) >= loop["max_seconds"]:
            budget_reasons.append("time_budget_exhausted")
        if budget_reasons:
            return {"allowed": True, "reasons": budget_reasons, "actionable": actionable}
        reasons: list[str] = []
        if not state["coverage"]:
            reasons.append("coverage_empty")
        elif any(entry["status"] == "not-tested" for entry in state["coverage"]):
            reasons.append("coverage_not_tested")
        elif any(entry["status"] == "blocked" for entry in state["coverage"]):
            reasons.append("operator_blocked")
        if actionable:
            reasons.append("actionable_leads")
        return {
            "allowed": not reasons,
            "reasons": reasons or ["converged"],
            "actionable": actionable,
        }

    def can_stop(self) -> dict[str, Any]:
        current = self._parse_time(self._now())

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            self._recover_stale(state, current)
            return self._can_stop(state, current)

        return self._mutate(operation)

    def record_iteration(
        self,
        progress: bool | None = None,
        *,
        progress_count: int | None = None,
        surface_delta: int = 0,
    ) -> dict[str, Any]:
        if progress is not None and not isinstance(progress, bool):
            raise LeadStateError("progress must be a boolean")
        if progress_count is None:
            progress_count = 1 if progress else 0
        for name, value in (("progress_count", progress_count), ("surface_delta", surface_delta)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LeadStateError(f"{name} must be a non-negative integer")
        current = self._parse_time(self._now())

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            state["loop"]["iterations"] += 1
            state["loop"]["progress_count"] += progress_count
            state["loop"]["surface_delta"] = surface_delta
            if progress_count > 0 or surface_delta > 0:
                state["loop"]["no_progress_rounds"] = 0
            else:
                state["loop"]["no_progress_rounds"] += 1
            return {"loop": state["loop"], "can_stop": self._can_stop(state, current)}

        return self._mutate(operation)

    def record_requests(self, count: int = 1) -> dict[str, Any]:
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise LeadStateError("request count must be a positive integer")
        current = self._parse_time(self._now())

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            state["loop"]["requests"] += count
            return {"loop": state["loop"], "can_stop": self._can_stop(state, current)}

        return self._mutate(operation)
