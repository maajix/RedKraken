#!/usr/bin/env python3
"""Strict engagement configuration parsing shared by harness utilities."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


class ConfigError(ValueError):
    pass


ROE_AUTHORIZATION_GATES = (
    "mutation_allowed",
    "sensitive_data_access_allowed",
    "credential_use_allowed",
    "pivoting_allowed",
    "availability_impact_allowed",
)
HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    loader.flatten_mapping(node)
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConfigError("engagement keys must be strings")
        if key in result:
            raise ConfigError(f"duplicate engagement key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_engagement(path: str | os.PathLike[str]) -> dict[str, Any]:
    yaml_path = Path(path)
    try:
        raw = yaml_path.read_text(encoding="utf-8")
        config = yaml.load(raw, Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError, ConfigError) as exc:
        raise ConfigError(f"cannot parse {yaml_path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ConfigError("engagement root must be a mapping")
    for key in ("targets", "out_of_scope", "egress_support", "audit_include", "audit_exclude"):
        if key not in config or config[key] is None:
            continue
        if not isinstance(config[key], list) or not all(isinstance(item, str) for item in config[key]):
            raise ConfigError(f"{key} must be a list of strings")
    for key in ("destructive_allowed", "rate_limit_enabled", *ROE_AUTHORIZATION_GATES):
        if key in config and not isinstance(config[key], bool):
            raise ConfigError(f"{key} must be true or false")
    for key in ("max_threads",):
        if key in config and (not isinstance(config[key], int) or isinstance(config[key], bool) or config[key] < 1):
            raise ConfigError(f"{key} must be a positive integer")
    if "rate_limit" in config:
        _validate_rate_limit(config["rate_limit"], "rate_limit")
    if config.get("rate_limit_enabled") is True and "rate_limit" not in config:
        raise ConfigError("rate_limit is required when rate_limit_enabled is true")
    if "required_headers" in config:
        _validate_required_headers(config["required_headers"])
    return config


def _validate_required_headers(value: Any) -> None:
    if not isinstance(value, dict):
        raise ConfigError("required_headers must be a mapping of header name to string value")
    if len(value) > 32:
        raise ConfigError("required_headers may contain at most 32 entries")
    seen: set[str] = set()
    for name, header_value in value.items():
        if not isinstance(name, str) or not HEADER_NAME_RE.fullmatch(name):
            raise ConfigError("required_headers contains an invalid header name")
        folded = name.casefold()
        if folded in seen:
            raise ConfigError("required_headers contains duplicate case-insensitive names")
        seen.add(folded)
        if (
            not isinstance(header_value, str)
            or not header_value
            or len(header_value) > 4096
            or "\r" in header_value
            or "\n" in header_value
        ):
            raise ConfigError("required_headers values must be non-empty injection-safe strings")


def roe_authorizations(config: dict[str, Any]) -> dict[str, bool]:
    """Resolve independent RoE gates, failing closed except for legacy mutation."""
    mutation_allowed = (
        config.get("mutation_allowed") is True
        if "mutation_allowed" in config
        else config.get("destructive_allowed") is True
    )
    return {
        "mutation_allowed": mutation_allowed,
        "sensitive_data_access_allowed": config.get("sensitive_data_access_allowed") is True,
        "credential_use_allowed": config.get("credential_use_allowed") is True,
        "pivoting_allowed": config.get("pivoting_allowed") is True,
        "availability_impact_allowed": config.get("availability_impact_allowed") is True,
    }


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{name} must be a positive number")
    return float(value)


def _validate_rate_values(value: dict[str, Any], name: str, *, allow_tools: bool) -> None:
    allowed = {"requests_per_second", "burst", "max_concurrency"}
    if allow_tools:
        allowed.add("per_tool")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{name} contains unknown keys: {', '.join(unknown)}")
    if "requests_per_second" in value:
        _positive_number(value["requests_per_second"], f"{name}.requests_per_second")
    for key in ("burst", "max_concurrency"):
        if key in value and (isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 1):
            raise ConfigError(f"{name}.{key} must be a positive integer")
    if allow_tools and "per_tool" in value:
        tools = value["per_tool"]
        if not isinstance(tools, dict) or not all(isinstance(tool, str) and tool for tool in tools):
            raise ConfigError(f"{name}.per_tool must be a mapping keyed by tool name")
        for tool, override in tools.items():
            if not isinstance(override, dict):
                raise ConfigError(f"{name}.per_tool.{tool} must be a mapping")
            _validate_rate_values(override, f"{name}.per_tool.{tool}", allow_tools=False)


def _validate_rate_limit(value: Any, name: str) -> None:
    # A positive integer is accepted for legacy engagement files, but is never
    # activated without rate_limit_enabled: true.
    if isinstance(value, int) and not isinstance(value, bool):
        _positive_number(value, name)
        return
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a positive integer or mapping")
    _validate_rate_values(value, name, allow_tools=True)
    if "requests_per_second" not in value:
        raise ConfigError("rate_limit.requests_per_second is required")


def rate_policy(config: dict[str, Any], tool: str = "") -> dict[str, float | int] | None:
    """Return the active rate policy; per-tool values may only tighten it."""
    if config.get("rate_limit_enabled") is not True:
        return None
    raw = config.get("rate_limit")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return {
            "requests_per_second": float(raw),
            "burst": raw,
            "max_concurrency": int(config.get("max_threads") or 1),
        }
    if not isinstance(raw, dict):
        raise ConfigError("rate_limit is required when rate_limit_enabled is true")
    base_rps = _positive_number(raw.get("requests_per_second"), "rate_limit.requests_per_second")
    base_burst = int(raw.get("burst", max(1, int(base_rps))))
    base_concurrency = int(raw.get("max_concurrency", config.get("max_threads") or 1))
    override = (raw.get("per_tool") or {}).get(tool) if tool else None
    if not override:
        return {
            "requests_per_second": base_rps,
            "burst": base_burst,
            "max_concurrency": base_concurrency,
        }
    override_rps = _positive_number(
        override.get("requests_per_second", base_rps),
        f"rate_limit.per_tool.{tool}.requests_per_second",
    )
    return {
        "requests_per_second": min(base_rps, override_rps),
        "burst": min(base_burst, int(override.get("burst", base_burst))),
        "max_concurrency": min(
            base_concurrency,
            int(override.get("max_concurrency", base_concurrency)),
        ),
    }


def engagement_yaml(candidate: str | os.PathLike[str]) -> Path:
    path = Path(candidate).expanduser()
    if path.is_dir():
        path = path / "engagement.yaml"
    if not path.is_file():
        raise ConfigError(f"engagement YAML not found: {path}")
    return path.resolve()


def resolve_engagement(
    explicit: str | None,
    *,
    root: Path,
    environ: dict[str, str] | None = None,
) -> Path:
    env = environ if environ is not None else os.environ
    candidate = explicit or env.get("PENTEST_ENGAGEMENT_DIR", "")
    if not candidate:
        active = root / ".active_engagement"
        try:
            candidate = active.read_text(encoding="utf-8").strip()
        except OSError:
            candidate = ""
    if not candidate:
        raise ConfigError("no engagement loaded")
    return engagement_yaml(candidate)


def normalized_hostname(value: str) -> str:
    host = value.strip().rstrip(".")
    if not host or any(ch.isspace() or ord(ch) < 32 for ch in host):
        raise ConfigError("empty or invalid host")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigError(f"invalid hostname: {value}") from exc


def extract_host(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ConfigError("empty host")
    try:
        return ipaddress.ip_address(candidate.strip("[]")).compressed.lower()
    except ValueError:
        pass
    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname
        if not host:
            raise ConfigError(f"cannot determine host from: {value}")
        # Accessing port validates malformed or out-of-range ports.
        _ = parsed.port
    except ValueError as exc:
        raise ConfigError(f"invalid URL or host: {value}") from exc
    return normalized_hostname(host)


def normalize_pattern(pattern: str) -> tuple[str, object]:
    value = pattern.strip()
    if not value:
        raise ConfigError("scope entries cannot be empty")
    if "/" in value:
        try:
            return "network", ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(f"invalid CIDR scope entry: {pattern}") from exc
    if value.startswith("*."):
        suffix = normalized_hostname(value[2:])
        if not suffix or suffix == "localhost":
            raise ConfigError(f"invalid wildcard scope entry: {pattern}")
        return "wildcard", suffix
    if any(token in value for token in ("://", "/", "?", "#", "@")):
        raise ConfigError(f"scope entries must be hosts or CIDRs, not URLs: {pattern}")
    return "exact", normalized_hostname(value)


def pattern_matches(host: str, pattern: str) -> bool:
    kind, normalized = normalize_pattern(pattern)
    if kind == "network":
        try:
            return ipaddress.ip_address(host) in normalized  # type: ignore[operator]
        except ValueError:
            return False
    if kind == "wildcard":
        return host.endswith(f".{normalized}") and host != normalized
    return host == normalized


def scope_decision(config: dict[str, Any], value: str) -> tuple[bool, str, str]:
    host = extract_host(value)
    targets = config.get("targets") or []
    denied = config.get("out_of_scope") or []
    # Parse every pattern before deciding so malformed deny entries fail closed.
    for pattern in [*targets, *denied]:
        normalize_pattern(pattern)
    for pattern in denied:
        if pattern_matches(host, pattern):
            return False, host, f"explicit out_of_scope: {pattern}"
    for pattern in targets:
        if pattern_matches(host, pattern):
            return True, host, "matched target"
    return False, host, "not in targets"


def config_sha256(path: str | os.PathLike[str]) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
