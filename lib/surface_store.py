#!/usr/bin/env python3
"""Atomic, idempotent inventory of normalized campaign surface observations."""

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


class SurfaceState:
    """Persist surface identity separately from the coordinator work queue."""

    def __init__(self, engagement: Path | str):
        self.directory = Path(engagement)
        self.state_dir = self.directory / "state"
        self.path = self.state_dir / "surface.json"
        self.lock_path = self.state_dir / ".surface.lock"

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
        return {"schema_version": 1, "revision": 0, "observations": []}

    def _prepare(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        state = json.loads(self.path.read_text(encoding="utf-8"))
        if (
            not isinstance(state, dict)
            or set(state) != {"schema_version", "revision", "observations"}
            or state["schema_version"] != 1
            or not isinstance(state["revision"], int)
            or not isinstance(state["observations"], list)
        ):
            raise ValueError("surface state does not match schema version 1")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        state["revision"] += 1
        fd, temporary = tempfile.mkstemp(
            prefix=".surface.", dir=self.state_dir, text=True
        )
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

    def snapshot(self) -> dict[str, Any]:
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            return copy.deepcopy(self._load())

    def observe(
        self,
        *,
        kind: str,
        value: str,
        parent: str,
        attributes: dict[str, Any],
        source: str,
    ) -> dict[str, Any]:
        identity = {"kind": kind, "value": value, "parent": parent}
        fingerprint = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        material = hashlib.sha256(
            json.dumps(attributes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        timestamp = self._now()
        self._prepare()
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._load()
            existing = next(
                (
                    item
                    for item in state["observations"]
                    if item["fingerprint"] == fingerprint
                ),
                None,
            )
            if existing is None:
                observation = {
                    "id": f"S-{fingerprint[:16]}",
                    "fingerprint": fingerprint,
                    **identity,
                    "attributes": attributes,
                    "material_sha256": material,
                    "sources": [source],
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                state["observations"].append(observation)
                result = "appended"
                self._write(state)
            elif existing["material_sha256"] != material:
                existing["attributes"] = attributes
                existing["material_sha256"] = material
                existing["sources"] = list(dict.fromkeys([*existing["sources"], source]))
                existing["updated_at"] = timestamp
                observation = existing
                result = "changed"
                self._write(state)
            else:
                observation = existing
                result = "duplicate"
                if source not in existing["sources"]:
                    existing["sources"].append(source)
                    existing["updated_at"] = timestamp
                    self._write(state)
            return {"result": result, "observation": copy.deepcopy(observation)}
