#!/usr/bin/env python3
"""Create or verify the immutable identity of an engagement run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness_config import ConfigError, config_sha256, engagement_yaml, load_engagement
from secure_engagement import secure_engagement


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXCLUDES = {".git", "node_modules", "vendor", "dist", ".next", "build"}


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def command(*argv: str) -> str:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=10, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def source_identity(config: dict[str, Any], yaml_path: Path) -> dict[str, Any]:
    raw_path = str(config.get("source_path") or "").strip()
    if not raw_path:
        return {}
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = (ROOT / candidate).resolve()
    if not candidate.exists():
        raise ConfigError(f"source_path does not exist: {candidate}")
    resolved = candidate.resolve()
    identity: dict[str, Any] = {"path": str(resolved)}
    git_root = command("git", "-C", str(resolved), "rev-parse", "--show-toplevel")
    if git_root:
        identity["git_root"] = str(Path(git_root).resolve())
        identity["head"] = command("git", "-C", git_root, "rev-parse", "HEAD")
        status = command("git", "-C", git_root, "status", "--porcelain=v1", "--untracked-files=all")
        identity["dirty"] = bool(status)
        identity["dirty_sha256"] = hashlib.sha256(status.encode()).hexdigest()
        source_ref = str(config.get("source_ref") or "").strip()
        if source_ref:
            base = command("git", "-C", git_root, "rev-parse", "--verify", f"{source_ref}^{{commit}}")
            if not base:
                raise ConfigError(f"source_ref does not resolve to a commit: {source_ref}")
            identity["source_ref"] = source_ref
            identity["source_base"] = base
    else:
        excludes = DEFAULT_EXCLUDES | set(config.get("audit_exclude") or [])
        digest = hashlib.sha256()
        for path in sorted(resolved.rglob("*")):
            try:
                relative = path.relative_to(resolved)
                if any(part in excludes for part in relative.parts) or not path.is_file():
                    continue
                stat = path.stat()
            except OSError:
                continue
            digest.update(f"{relative}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
        identity["tree_metadata_sha256"] = digest.hexdigest()
    return identity


def tool_paths() -> dict[str, str]:
    names = ("curl", "jq", "python3", "rg", "httpx", "nuclei", "mitmdump", "playwright", "schemathesis")
    return {name: path for name in names if (path := shutil.which(name))}


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def identity_payload(yaml_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    source = source_identity(config, yaml_path)
    stable = {
        "engagement_yaml": str(yaml_path),
        "config_sha256": config_sha256(yaml_path),
        "source": source,
        "targets": config.get("targets") or [],
        "out_of_scope": config.get("out_of_scope") or [],
    }
    encoded = json.dumps(stable, separators=(",", ":"), sort_keys=True).encode()
    return {**stable, "context_sha256": hashlib.sha256(encoded).hexdigest()}


def legacy_identity_payload(
    yaml_path: Path, config: dict[str, Any], mode: str
) -> dict[str, Any]:
    stable = {"mode": mode, **identity_payload(yaml_path, config)}
    stable.pop("context_sha256")
    encoded = json.dumps(stable, separators=(",", ":"), sort_keys=True).encode()
    return {**stable, "context_sha256": hashlib.sha256(encoded).hexdigest()}


def record_phase(payload: dict[str, Any], phase: str) -> None:
    history = payload.setdefault("phase_history", [])
    if payload.get("current_phase") != phase:
        history.append({"phase": phase, "entered_at": now()})
    payload["current_phase"] = phase


def validate_mode(config: dict[str, Any], mode: str) -> None:
    if not str(config.get("intent") or "").strip():
        raise ConfigError("intent is required")
    if mode in {"pentest", "recon"} and not config.get("targets"):
        raise ConfigError(f"targets are required for {mode}")
    if mode == "audit" and not str(config.get("source_path") or "").strip():
        raise ConfigError("source_path is required for audit")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engagement")
    parser.add_argument("--mode", choices=("pentest", "recon", "audit", "report"), required=True)
    args = parser.parse_args(argv[1:])
    try:
        yaml_path = engagement_yaml(args.engagement)
        directory = yaml_path.parent
        config = load_engagement(yaml_path)
        validate_mode(config, args.mode)
        identity = identity_payload(yaml_path, config)
        state = directory / "state"
        evidence = directory / "evidence"
        directory.chmod(0o700)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
        state.chmod(0o700)
        evidence.chmod(0o700)
        secure_engagement(directory)
        run_path = state / "run.json"
        if run_path.exists():
            previous = json.loads(run_path.read_text(encoding="utf-8"))
            if previous.get("context_sha256") != identity["context_sha256"]:
                legacy_mode = previous.get("mode")
                legacy = (
                    legacy_identity_payload(yaml_path, config, legacy_mode)
                    if previous.get("schema_version") == 1
                    and isinstance(legacy_mode, str)
                    else None
                )
                if legacy is None or previous.get("context_sha256") != legacy["context_sha256"]:
                    print("STALE_RUN_CONTEXT: engagement config or source identity changed", file=sys.stderr)
                    print(f"previous={previous.get('context_sha256', '')}", file=sys.stderr)
                    print(f"current={identity['context_sha256']}", file=sys.stderr)
                    return 3
            previous.update(identity)
            previous.pop("mode", None)
            previous["schema_version"] = 2
            record_phase(previous, args.mode)
            previous["last_verified"] = now()
            previous["tool_paths"] = tool_paths()
            atomic_json(run_path, previous)
            result = "RESUME"
        else:
            payload = {
                **identity,
                "schema_version": 2,
                "run_id": str(uuid.uuid4()),
                "started_at": now(),
                "last_verified": now(),
                "tool_paths": tool_paths(),
            }
            record_phase(payload, args.mode)
            atomic_json(run_path, payload)
            result = "NEW_RUN"
        active = ROOT / ".active_engagement"
        active.write_text(str(directory.resolve()) + "\n", encoding="utf-8")
        active.chmod(0o600)
        secure_engagement(directory)
        print(f"{result} {directory} context={identity['context_sha256']}")
        return 0
    except (ConfigError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"run_context: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
