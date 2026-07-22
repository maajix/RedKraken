#!/usr/bin/env python3
"""Durable kill-chain review: nodes, prerequisite edges, and a checkpoint.

Chain state lives beside the lead queue rather than inside it.  A chain edge is
grounded in evidence: it exists only when a *demonstrated* capability satisfies
another observation's declared prerequisite, so the graph never speculates past
proven facts.  A single reviewable checkpoint records the material revision it
last certified, so any later material change reopens chain review.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any


SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_ASSIGNMENTS = 64


class ChainStateError(ValueError):
    """Raised when a chain node or operation violates the module interface."""


def _ordered_union(*lists: list[str]) -> list[str]:
    merged: list[str] = []
    for values in lists:
        merged.extend(values)
    return list(dict.fromkeys(merged))


class ChainState:
    """Own the evidence-grounded kill-chain graph and its review checkpoint."""

    def __init__(self, engagement: Path | str):
        self.directory = Path(engagement)
        self.state_dir = self.directory / "state"
        self.path = self.state_dir / "chain-state.json"
        self.lock_path = self.state_dir / ".chain-state.lock"

    @staticmethod
    def _now() -> str:
        return (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "schema_version": 1,
            "revision": 0,
            "material_revision": 0,
            "nodes": [],
            "assignments": [],
            "review": {"status": "stale", "certified_revision": None, "certified_at": None},
        }

    def _prepare(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        state = json.loads(self.path.read_text(encoding="utf-8"))
        if (
            not isinstance(state, dict)
            or set(state) != set(self._empty())
            or state["schema_version"] != 1
        ):
            raise ChainStateError("chain state does not match schema version 1")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        state["revision"] += 1
        fd, temporary = tempfile.mkstemp(prefix=".chain-state.", dir=self.state_dir, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    @staticmethod
    def _string_list(value: Any, field: str) -> list[str]:
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            raise ChainStateError(f"{field} must be an array of non-empty strings")
        return list(dict.fromkeys(item.strip() for item in value))

    @classmethod
    def _normalize_node(cls, raw: Any) -> dict[str, Any]:
        allowed = {
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
        }
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise ChainStateError("chain node fields do not match the contract")
        source_id = raw.get("source_id")
        asset = raw.get("asset")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ChainStateError("source_id must be a non-empty string")
        if not isinstance(asset, str) or not asset.strip():
            raise ChainStateError("asset must be a non-empty string")
        severity = raw.get("severity", "info")
        if severity not in SEVERITIES:
            raise ChainStateError(f"severity must be one of: {', '.join(SEVERITIES)}")
        status = raw.get("status", "observed")
        if status not in {"observed", "demonstrated"}:
            raise ChainStateError("status must be observed or demonstrated")
        authorized = raw.get("authorized", True)
        if not isinstance(authorized, bool):
            raise ChainStateError("authorized must be a boolean")
        title = raw.get("title", "")
        if not isinstance(title, str):
            raise ChainStateError("title must be a string")
        fingerprint = hashlib.sha256(source_id.strip().encode()).hexdigest()
        return {
            "id": f"N-{fingerprint[:16]}",
            "source_id": source_id.strip(),
            "asset": asset.strip(),
            "title": title.strip(),
            "provides": cls._string_list(raw.get("provides", []), "provides"),
            "requires": cls._string_list(raw.get("requires", []), "requires"),
            "severity": severity,
            "authorized": authorized,
            "status": status,
            "evidence": cls._string_list(raw.get("evidence", []), "evidence"),
            "safety_requirements": cls._string_list(
                raw.get("safety_requirements", []), "safety_requirements"
            ),
        }

    @staticmethod
    def _material_signature(node: dict[str, Any]) -> tuple[Any, ...]:
        return (
            node["source_id"],
            node["asset"],
            node["title"],
            tuple(sorted(node["provides"])),
            tuple(sorted(node["requires"])),
            node["severity"],
            node["authorized"],
            node["status"],
            tuple(node["evidence"]),
            tuple(node["safety_requirements"]),
        )

    @classmethod
    def _combined_severity(cls, left: str, right: str) -> str:
        return left if SEVERITIES.index(left) >= SEVERITIES.index(right) else right

    @classmethod
    def _recompute(cls, state: dict[str, Any]) -> None:
        """Rebuild edges from demonstrated capabilities that meet a prerequisite."""
        by_source = {node["source_id"]: node for node in state["nodes"]}
        existing = {item["id"]: item for item in state["assignments"]}
        rebuilt: list[dict[str, Any]] = []
        for provider in state["nodes"]:
            if provider["status"] != "demonstrated":
                continue  # Edges start only from a proven capability.
            for consumer in state["nodes"]:
                if consumer["source_id"] == provider["source_id"]:
                    continue
                # The link is a satisfied prerequisite token, never a shared asset.
                for token in sorted(set(provider["provides"]) & set(consumer["requires"])):
                    digest = hashlib.sha256(
                        f"{provider['source_id']}\0{consumer['source_id']}\0{token}".encode()
                    ).hexdigest()
                    edge_id = f"K-{digest[:16]}"
                    prior = existing.get(edge_id)
                    provisional = cls._combined_severity(
                        provider["severity"], consumer["severity"]
                    )
                    assignment = {
                        "id": edge_id,
                        "provider": provider["source_id"],
                        "consumer": consumer["source_id"],
                        "token": token,
                        "parents": [provider["source_id"], consumer["source_id"]],
                        "asset": consumer["asset"],
                        "required_evidence": _ordered_union(
                            provider["evidence"], consumer["evidence"]
                        ),
                        "safety_requirements": _ordered_union(
                            provider["safety_requirements"], consumer["safety_requirements"]
                        ),
                        "title": consumer["title"]
                        or f"Chain {provider['source_id']} into {consumer['source_id']}",
                        "severity": provisional,
                        "status": "blocked" if not consumer["authorized"] else "candidate",
                        "evidence": [],
                        "reason": "",
                    }
                    if prior is not None and prior["status"] in {
                        "validated",
                        "not-demonstrated",
                    }:
                        assignment["status"] = prior["status"]
                        assignment["severity"] = prior["severity"]
                        assignment["evidence"] = prior["evidence"]
                        assignment["title"] = prior["title"]
                        assignment["reason"] = prior.get("reason", "")
                    elif prior is not None and prior["status"] == "blocked" and consumer["authorized"]:
                        assignment["status"] = "candidate"
                    rebuilt.append(assignment)
        # Bound unresolved work deterministically; reviewed edges always survive.
        reviewed = [
            item
            for item in rebuilt
            if item["status"] in {"validated", "not-demonstrated"}
        ]
        others = sorted(
            (
                item
                for item in rebuilt
                if item["status"] not in {"validated", "not-demonstrated"}
            ),
            key=lambda item: (-SEVERITIES.index(item["severity"]), item["id"]),
        )
        budget = max(0, MAX_ASSIGNMENTS - len(reviewed))
        state["assignments"] = sorted(
            [*reviewed, *others[:budget]], key=lambda item: item["id"]
        )
        _ = by_source  # nodes are the authoritative component findings; never rewritten

    def snapshot(self) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            state = self._load()
            state["review_pending"] = self._review_pending(state)
            return copy.deepcopy(state)

    @staticmethod
    def _review_pending(state: dict[str, Any]) -> bool:
        review = state["review"]
        return (
            review["status"] != "certified"
            or review["certified_revision"] != state["material_revision"]
        )

    def _mutate(self, operation: Any) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._load()
            result = operation(state)
            self._write(state)
            return copy.deepcopy(result)

    def mark_material(self) -> dict[str, Any]:
        """Record that a material lead or finding revision occurred elsewhere."""

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            state["material_revision"] += 1
            state["review"]["status"] = "stale"
            return {"material_revision": state["material_revision"]}

        return self._mutate(operation)

    def observe(self, raw: Any) -> dict[str, Any]:
        node = self._normalize_node(raw)

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            existing = next(
                (item for item in state["nodes"] if item["id"] == node["id"]), None
            )
            if existing is None:
                state["nodes"].append(node)
                result = "appended"
                changed = True
            elif self._material_signature(existing) != self._material_signature(node):
                existing.update(node)
                result = "changed"
                changed = True
            else:
                existing.update(node)
                result = "duplicate"
                changed = False
            if changed:
                state["material_revision"] += 1
                state["review"]["status"] = "stale"
            self._recompute(state)
            stored = next(item for item in state["nodes"] if item["id"] == node["id"])
            return {
                "result": result,
                "node": stored,
                "assignments": [
                    item
                    for item in state["assignments"]
                    if node["source_id"] in item["parents"]
                ],
                "review_pending": self._review_pending(state),
            }

        return self._mutate(operation)

    def certify(self) -> dict[str, Any]:
        """Certify the current material revision without altering it."""

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            unresolved = [
                item["id"]
                for item in state["assignments"]
                if item["status"] == "candidate"
            ]
            if unresolved:
                raise ChainStateError(
                    "resolve candidate chain assignments before certification: "
                    + ", ".join(unresolved)
                )
            state["review"] = {
                "status": "certified",
                "certified_revision": state["material_revision"],
                "certified_at": self._now(),
            }
            return {"review": state["review"], "review_pending": False}

        return self._mutate(operation)

    def reject(
        self, assignment_id: str, evidence: list[str] | None = None, reason: str = ""
    ) -> dict[str, Any]:
        """Close a tested candidate whose prerequisite did not produce a chain."""

        merged = self._string_list(evidence or [], "evidence")
        if not merged:
            raise ChainStateError("a rejected chain candidate requires negative evidence")
        if not isinstance(reason, str) or not reason.strip():
            raise ChainStateError("a rejected chain candidate requires a reason")

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            assignment = next(
                (item for item in state["assignments"] if item["id"] == assignment_id),
                None,
            )
            if assignment is None:
                raise ChainStateError(f"unknown chain assignment: {assignment_id}")
            if assignment["status"] == "blocked":
                raise ChainStateError("a false authorization gate already blocks this chain edge")
            if assignment["status"] == "validated":
                raise ChainStateError("a validated chain edge cannot be rejected")
            assignment["status"] = "not-demonstrated"
            assignment["evidence"] = _ordered_union(assignment["evidence"], merged)
            assignment["reason"] = reason.strip()
            state["material_revision"] += 1
            state["review"]["status"] = "stale"
            return assignment

        return self._mutate(operation)

    def validate(
        self,
        assignment_id: str,
        severity: str,
        evidence: list[str] | None = None,
        title: str = "",
    ) -> dict[str, Any]:
        if severity not in SEVERITIES:
            raise ChainStateError(f"severity must be one of: {', '.join(SEVERITIES)}")
        merged = self._string_list(evidence or [], "evidence")
        if not merged:
            raise ChainStateError("a validated chain requires demonstrated evidence")

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            assignment = next(
                (item for item in state["assignments"] if item["id"] == assignment_id),
                None,
            )
            if assignment is None:
                raise ChainStateError(f"unknown chain assignment: {assignment_id}")
            if assignment["status"] == "blocked":
                raise ChainStateError("a false authorization gate blocks this chain edge")
            assignment["status"] = "validated"
            assignment["severity"] = severity
            assignment["evidence"] = _ordered_union(assignment["evidence"], merged)
            if title.strip():
                assignment["title"] = title.strip()
            state["material_revision"] += 1
            state["review"]["status"] = "stale"
            finding = {
                "id": f"CF-{assignment_id[2:]}",
                "kind": "chain",
                "title": assignment["title"],
                "severity": severity,
                "parents": list(assignment["parents"]),
                "components": list(assignment["parents"]),
                "evidence": list(assignment["evidence"]),
                "assignment_id": assignment_id,
            }
            return finding

        return self._mutate(operation)
