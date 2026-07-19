#!/usr/bin/env python3
"""Durable convergence-challenge bookkeeping.

Before an apparently converged campaign may transition to reporting, three
isolated explorer lenses each reason over the *same* material digest and submit
structured leads.  This store records only the challenge round: which lenses have
reported, which digest the round is bound to, and whether a unique lead was
accepted.  It never holds campaign leads, so certifying a round cannot change the
material digest it certifies.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Callable


LENSES = ("surface-archaeologist", "abuse-case-adversary", "boundary-breaker")


class ChallengeStateError(ValueError):
    """Raised when a challenge operation violates the module interface."""


class ChallengeState:
    """Own the convergence-challenge checkpoint separately from campaign work."""

    def __init__(self, engagement: Path | str):
        self.directory = Path(engagement)
        self.state_dir = self.directory / "state"
        self.path = self.state_dir / "challenge-state.json"
        self.lock_path = self.state_dir / ".challenge-state.lock"

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
            "status": "idle",
            "digest": None,
            "lenses": {lens: "pending" for lens in LENSES},
            "accepted_ids": [],
            "rejected": [],
            "updated_at": None,
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
            raise ChallengeStateError("challenge state does not match schema version 1")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        state["revision"] += 1
        state["updated_at"] = self._now()
        fd, temporary = tempfile.mkstemp(prefix=".challenge-state.", dir=self.state_dir, text=True)
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

    def _mutate(self, operation: Callable[[dict[str, Any]], Any]) -> Any:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._load()
            result = operation(state)
            self._write(state)
            return copy.deepcopy(result)

    def snapshot(self) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            return copy.deepcopy(self._load())

    def open(self, digest: str) -> dict[str, Any]:
        """Schedule all three lenses for the given digest, idempotently."""
        if not isinstance(digest, str) or not digest.strip():
            raise ChallengeStateError("digest must be a non-empty string")

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            if state["digest"] == digest and state["status"] in {"open", "certified"}:
                return state  # A round for this exact digest is already live.
            state["status"] = "open"
            state["digest"] = digest
            state["lenses"] = {lens: "pending" for lens in LENSES}
            state["accepted_ids"] = []
            state["rejected"] = []
            return state

        return self._mutate(operation)

    def record(
        self,
        lens: str,
        digest: str,
        accepted_ids: list[str],
        rejected: list[dict[str, str]],
    ) -> dict[str, Any]:
        if lens not in LENSES:
            raise ChallengeStateError(f"lens must be one of: {', '.join(LENSES)}")

        def operation(state: dict[str, Any]) -> dict[str, Any]:
            if state["digest"] != digest or state["status"] not in {"open", "reopened"}:
                raise ChallengeStateError("no open challenge matches this digest")
            state["lenses"][lens] = "submitted"
            state["accepted_ids"] = list(
                dict.fromkeys([*state["accepted_ids"], *accepted_ids])
            )
            state["rejected"].extend(rejected)
            if state["accepted_ids"]:
                # One accepted unique lead reopens normal campaign work.
                state["status"] = "reopened"
            elif all(value == "submitted" for value in state["lenses"].values()):
                state["status"] = "certified"
            return state

        return self._mutate(operation)

    def reporting_permitted(self, current_digest: str) -> bool:
        state = self.snapshot()
        return state["status"] == "certified" and state["digest"] == current_digest
