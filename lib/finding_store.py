#!/usr/bin/env python3
"""Concurrent, schema-backed finding creation and update store."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {
    "suspected",
    "confirmed",
    "exploited",
    "exploitable-not-detonated",
    "not-exploitable",
    "not-tested",
}
STATUS_RANK = {
    "not-tested": 0,
    "suspected": 0,
    "not-exploitable": 1,
    "confirmed": 2,
    "exploitable-not-detonated": 3,
    "exploited": 4,
}
ARRAY_FIELDS = {"evidence", "repro", "dataflow", "references", "standards"}


class FindingError(ValueError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def engagement_dir(explicit: str | None) -> Path:
    value = explicit or os.environ.get("PENTEST_ENGAGEMENT_DIR", "")
    if not value:
        try:
            value = (ROOT / ".active_engagement").read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
    if not value:
        raise FindingError("no engagement dir (pass --engagement or set PENTEST_ENGAGEMENT_DIR)")
    return Path(value).expanduser().resolve()


def _strings(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise FindingError(f"{field} must be an array of strings")
    return value


def normalize(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FindingError("finding must be a JSON object")
    finding = dict(raw)
    finding["schema_version"] = 1
    for field in ("id", "technique", "family", "summary"):
        if not isinstance(finding.get(field), str) or not finding[field].strip():
            raise FindingError(f"{field} is required and must be a non-empty string")
        finding[field] = finding[field].strip()
    if not ID_RE.fullmatch(finding["id"]):
        raise FindingError("id contains unsupported characters")
    severity = str(finding.get("severity", "")).lower()
    if severity not in SEVERITIES:
        raise FindingError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
    finding["severity"] = severity
    status = finding.get("status", "")
    if isinstance(status, str) and status.startswith("not-tested (") and status.endswith(")"):
        finding.setdefault("status_reason", status[len("not-tested (") : -1])
        status = "not-tested"
    if status not in STATUSES:
        raise FindingError(f"status must be one of: {', '.join(sorted(STATUSES))}")
    finding["status"] = status
    finding.setdefault("source", "blackbox" if finding.get("endpoint") else "manual")
    if not isinstance(finding["source"], str) or not finding["source"].strip():
        raise FindingError("source must be a non-empty string")
    for field in ARRAY_FIELDS:
        finding[field] = _strings(finding.get(field), field)
    finding.setdefault("impact", "")
    finding.setdefault("remediation", "")
    finding.setdefault("ts", now())
    if "line" in finding and (not isinstance(finding["line"], int) or isinstance(finding["line"], bool) or finding["line"] < 1):
        raise FindingError("line must be a positive integer")
    if finding.get("file") and "line" not in finding:
        raise FindingError("white-box findings with file require line")
    if status in {"confirmed", "exploited", "exploitable-not-detonated"} and not finding["evidence"]:
        raise FindingError(f"{status} findings require at least one evidence path")
    if status == "exploited" and not str(finding.get("impact", "")).strip():
        raise FindingError("exploited findings require impact")
    if not any(finding.get(field) for field in ("endpoint", "file", "component")) and status != "not-tested":
        raise FindingError("finding requires endpoint, file, or component")
    return finding


def fingerprint(finding: dict[str, Any]) -> tuple[str, ...]:
    technique = finding.get("technique", "").casefold()
    if finding.get("file"):
        return ("whitebox", technique, str(finding["file"]), str(finding.get("line", "")))
    if finding.get("endpoint"):
        return (
            "blackbox",
            technique,
            str(finding.get("method", "GET")).upper(),
            str(finding["endpoint"]),
            str(finding.get("param", "")),
        )
    if finding.get("component"):
        return ("component", technique, str(finding["component"]))
    return ("id", str(finding["id"]))


def merge(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    if fingerprint(existing) != fingerprint(incoming):
        raise FindingError(f"finding id {incoming['id']} cannot change identity fields")
    merged = dict(existing)
    for key, value in incoming.items():
        if key in ARRAY_FIELDS:
            merged[key] = list(dict.fromkeys([*existing.get(key, []), *value]))
        elif key not in {"id", "schema_version", "ts"} and value not in (None, ""):
            merged[key] = value
    old_status = existing.get("status", "suspected")
    new_status = incoming.get("status", old_status)
    if STATUS_RANK.get(new_status, -1) < STATUS_RANK.get(old_status, -1):
        merged["status"] = old_status
    merged["updated_ts"] = now()
    return normalize(merged)


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FindingError(f"existing findings.jsonl line {number} is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise FindingError(f"existing findings.jsonl line {number} is not an object")
        rows.append(value)
    return rows


def atomic_write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".findings.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def upsert(directory: Path, raw: Any) -> str:
    incoming = normalize(raw)
    state = directory / "state"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)
    path = state / "findings.jsonl"
    lock_path = state / ".findings.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(lock_fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rows = load_rows(path)
            id_index = next((i for i, row in enumerate(rows) if row.get("id") == incoming["id"]), None)
            if id_index is not None:
                updated = merge(rows[id_index], incoming)
                if updated == rows[id_index]:
                    return "duplicate"
                rows[id_index] = updated
                atomic_write(path, rows)
                return "updated"
            incoming_fp = fingerprint(incoming)
            if any(fingerprint(row) == incoming_fp for row in rows):
                return "duplicate"
            rows.append(incoming)
            atomic_write(path, rows)
            return "appended"
    finally:
        pass


def selftest() -> int:
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        base = {
            "technique": "SQLi",
            "family": "injection",
            "severity": "high",
            "status": "suspected",
            "summary": "candidate SQL injection",
        }
        print(upsert(directory, {**base, "id": "F-1", "endpoint": "https://app.test/one", "param": "id"}))
        print(upsert(directory, {**base, "id": "F-2", "endpoint": "https://app.test/two", "param": "id"}))
        result = upsert(
            directory,
            {
                **base,
                "id": "F-1",
                "endpoint": "https://app.test/one",
                "param": "id",
                "status": "exploited",
                "evidence": ["evidence/F-1/response.txt"],
                "impact": "read access demonstrated",
            },
        )
        rows = load_rows(directory / "state/findings.jsonl")
        print(f"{result} rows={len(rows)} first_status={rows[0]['status']}")
        return 0 if result == "updated" and len(rows) == 2 and rows[0]["status"] == "exploited" else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("json", nargs="?")
    parser.add_argument("--engagement")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv[1:])
    if args.selftest:
        return selftest()
    try:
        text = args.json if args.json is not None else sys.stdin.read()
        raw = json.loads(text)
        print(upsert(engagement_dir(args.engagement), raw))
        return 0
    except (FindingError, json.JSONDecodeError, OSError) as exc:
        print(f"record_finding: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
