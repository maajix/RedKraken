#!/usr/bin/env python3
"""Read-only, value-redacted engagement retention and hygiene inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from harness_config import ConfigError, load_engagement  # noqa: E402


SECRET_NAME_RE = re.compile(r"(?i)(credential|password|passwd|token|cookie|secret|api[-_]?key|session)")
SECRET_VALUE_RE = re.compile(
    r"(?im)(?:authorization\s*:\s*(?:bearer|basic)|password|passwd|token|cookie|secret|api[_-]?key)\s*[:=]\s*([^\s]+)"
)
NETWORK_KEYS = {"targets", "out_of_scope", "egress_support", "oob_host", "callback_host", "callback_url"}
ALWAYS_RECORD = {"engagement.yaml", "audit.jsonl", "report.md"}


def tracked_engagement_paths(root: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", "engagements"], cwd=root,
            check=True, capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {item.decode("utf-8", errors="replace") for item in result.stdout.split(b"\0") if item}


def repo_state(path: Path, repo_root: Path = ROOT) -> str:
    try:
        relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return "external"
    checks = (
        ("tracked", ["git", "ls-files", "--error-unmatch", "--", relative]),
        ("ignored", ["git", "check-ignore", "-q", "--", relative]),
    )
    for state, command in checks:
        result = subprocess.run(command, cwd=repo_root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return state
    result = subprocess.run(
        ["git", "log", "--all", "-1", "--format=%H", "--", relative],
        cwd=repo_root, text=True, capture_output=True,
    )
    return "historical" if result.returncode == 0 and result.stdout.strip() else "untracked"


def _walk_no_links(root: Path) -> Iterator[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in sorted(entries, key=lambda item: item.name):
            path = Path(entry.path)
            if entry.is_symlink():
                yield path
            elif entry.is_dir(follow_symlinks=False):
                stack.append(path)
            elif entry.is_file(follow_symlinks=False):
                yield path


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _strings(nested)


def _network_identifiers(config: dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    for key in NETWORK_KEYS:
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            identifiers.add(value.strip())
        elif isinstance(value, list):
            identifiers.update(item.strip() for item in value if isinstance(item, str) and item.strip())
    return identifiers


def _references(root: Path) -> tuple[set[str], list[str]]:
    references: set[str] = set()
    warnings: list[str] = []
    state = root / "state"
    if not state.is_dir() or state.is_symlink():
        return references, warnings
    for path in _walk_no_links(state):
        if path.is_symlink() or path.stat().st_size > 5 * 1024 * 1024:
            continue
        if path.suffix not in {".json", ".jsonl"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines() if path.suffix == ".jsonl" else [path.read_text(encoding="utf-8")]
            for line in lines:
                if line.strip():
                    references.update(item for item in _strings(json.loads(line)) if "/" in item)
        except (OSError, UnicodeError, json.JSONDecodeError):
            warnings.append(f"unreadable state reference file: {path.relative_to(root)}")
    return references, warnings


def _reference_count(relative: str, references: set[str]) -> int:
    normalized = relative.removeprefix("./")
    return sum(1 for value in references if value.removeprefix("./") == normalized or value.endswith("/" + normalized))


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _secret_rules(path: Path) -> list[str]:
    rules: list[str] = []
    if SECRET_NAME_RE.search(path.name):
        rules.append("credential-like-filename")
    try:
        if path.stat().st_size <= 1024 * 1024:
            text = path.read_text(encoding="utf-8", errors="replace")
            if SECRET_VALUE_RE.search(text):
                rules.append("credential-assignment")
    except OSError:
        pass
    return rules


def _row(root: Path, path: Path, references: set[str], expired: bool, deletion_blocked: bool) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    symlink = path.is_symlink()
    mode = stat.S_IMODE(path.lstat().st_mode)
    count = _reference_count(relative, references)
    rules = [] if symlink else _secret_rules(path)
    class_name = "D"
    reason = "unreferenced runtime artifact"
    action = "archive"
    if symlink:
        class_name, reason, action = "D", "symbolic link not followed; operator review required", "preserve"
    elif relative == "engagement.yaml":
        class_name, reason, action = "A", "scope and operational configuration", "preserve"
    elif relative == "audit.jsonl" or relative == "report.md" or relative.startswith("evidence/") or relative.endswith("findings.jsonl"):
        class_name, reason, action = "C", "audit, finding, report, or evidence record", "preserve"
    elif count:
        class_name, reason, action = "C", "referenced by engagement state", "preserve"
    elif rules:
        if expired and "synthetic" in path.name.lower():
            class_name, reason, action = "D", "expired unreferenced synthetic credential", "delete"
        else:
            class_name, reason, action = "B", "credential-like content or filename", "rotate-then-delete"
    elif relative.startswith("state/"):
        class_name, reason, action = "D", "unreferenced state artifact; retention review required", "archive"
    else:
        class_name, reason, action = "C", "engagement record outside disposable state", "preserve"
    if deletion_blocked and action in {"delete", "rotate-then-delete"}:
        action = "preserve"
        reason = "configuration/reference warning blocks deletion"
    return {
        "path": relative,
        "class": class_name,
        "reason": reason,
        "tracked_state": repo_state(path),
        "sha256": "" if symlink else _file_hash(path),
        # Low-entropy secret hashes enable offline guessing. The whole-file hash
        # above is retained only for deletion-manifest integrity; never emit a
        # separately reusable value hash for credential-like content.
        "value_sha256": "",
        "secret_rules": rules,
        "referenced_by": [] if count == 0 else ["engagement-state"],
        "reference_count": count,
        "preserved_identifiers": [],
        "rotation_status": "not-required" if class_name != "B" else "required-before-delete",
        "archive_status": "not-evaluated",
        "action": action,
        "verification": "report-only; no mutation",
        "operator_decision": "pending",
        "mode": f"0{mode:o}",
        "permission_secure": mode == (0o777 if symlink else 0o600),
        "symlink": symlink,
    }


def audit_engagement(directory: Path) -> dict[str, Any]:
    root = directory.expanduser().resolve()
    warnings: list[str] = []
    config: dict[str, Any] = {}
    deletion_blocked = False
    try:
        config = load_engagement(root / "engagement.yaml")
    except ConfigError:
        warnings.append("malformed or missing engagement configuration")
        deletion_blocked = True
    references, reference_warnings = _references(root)
    warnings.extend(reference_warnings)
    if reference_warnings:
        deletion_blocked = True
    retention = config.get("retention") if isinstance(config.get("retention"), dict) else {}
    expired = str(retention.get("status", "")).lower() == "expired"
    rows = [_row(root, path, references, expired, deletion_blocked) for path in _walk_no_links(root)]
    root_mode = stat.S_IMODE(root.stat().st_mode)
    return {
        "engagement": root.name,
        "deletion_blocked": deletion_blocked,
        "warnings": warnings,
        "permissions": {"directory_mode": f"0{root_mode:o}", "directory_secure": root_mode == 0o700},
        "preservation_set": {
            "network_identifiers": sorted(_network_identifiers(config)),
            "referenced_paths": sorted(references),
        },
        "files": rows,
    }


def emit_report(report: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    print(
        f"engagement={report['engagement']} files={len(report['files'])} "
        f"deletion_blocked={str(report['deletion_blocked']).lower()}"
    )
    for row in report["files"]:
        print(f"{row['action']:18} class={row['class']} mode={row['mode']} path={row['path']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement", type=Path)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    try:
        report = audit_engagement(args.engagement)
        emit_report(report, json_output=args.json_output)
        return 1 if report["deletion_blocked"] else 0
    except OSError as exc:
        print(f"hygiene audit error: {exc.strerror or 'filesystem error'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
