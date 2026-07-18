#!/usr/bin/env python3
"""Create a draft harness engagement from a public Intigriti program."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit

import yaml


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.harness_config import ConfigError, extract_host, load_engagement, normalize_pattern, pattern_matches


HANDLE_RE = re.compile(r"[A-Za-z0-9_-]+")
DOMAIN_RE = re.compile(
    r"(?<![@A-Za-z0-9_.-])(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![@A-Za-z0-9_.-])"
)
RATE_RE = re.compile(
    r"\b(\d+)\s*(?:requests?|req(?:uests?)?)\s*(?:per|/)\s*(?:second|sec)\b",
    re.IGNORECASE,
)
USERNAME_PLACEHOLDER_RE = re.compile(r"(?:<\s*username\s*>|\{\s*username\s*\})", re.IGNORECASE)
SEVERITY_FLOORS = (
    (9.5, "exceptional"),
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
)
NON_WEB_TYPES = {2: "Android package", 3: "iOS store id", 6: "Other"}
ROE_GATES = (
    "mutation_allowed",
    "sensitive_data_access_allowed",
    "credential_use_allowed",
    "pivoting_allowed",
    "availability_impact_allowed",
    "destructive_allowed",
)


class DraftDumper(yaml.SafeDumper):
    """Readable YAML dumper that uses literal blocks for assembled prose."""


def _represent_string(dumper: DraftDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


DraftDumper.add_representer(str, _represent_string)


def parse_program_ref(value: str) -> tuple[str, str]:
    candidate = value.strip()
    if not candidate:
        raise ValueError("program reference must be an Intigriti URL or company/program slug")

    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != "app.intigriti.com":
            raise ValueError("program URL must be on app.intigriti.com")
        segments = [unquote(segment) for segment in parsed.path.split("/") if segment]
        try:
            programs_at = segments.index("programs")
            company, program = segments[programs_at + 1 : programs_at + 3]
        except (ValueError, IndexError) as exc:
            raise ValueError("cannot extract company/program from Intigriti URL") from exc
    else:
        segments = candidate.strip("/").split("/")
        if len(segments) != 2:
            raise ValueError("program slug must use company/program format")
        company, program = segments

    if not HANDLE_RE.fullmatch(company) or not HANDLE_RE.fullmatch(program):
        raise ValueError("program slug must use valid company/program handles")
    return company, program


def _latest_snapshot(program: dict[str, Any], key: str) -> dict[str, Any]:
    snapshots = program.get(key)
    if not isinstance(snapshots, list) or not snapshots:
        raise ValueError(f"program has no {key} snapshots")
    valid = [item for item in snapshots if isinstance(item, dict) and isinstance(item.get("createdAt"), (int, float))]
    if not valid:
        raise ValueError(f"program has no valid {key} snapshots")
    latest = max(valid, key=lambda item: item["createdAt"])
    content = latest.get("content")
    if not isinstance(content, dict):
        raise ValueError(f"latest {key} snapshot has invalid content")
    return content


def _severity_label(score: float) -> str:
    for minimum, label in SEVERITY_FLOORS:
        if score >= minimum:
            return label
    raise ValueError(f"invalid paid CVSS floor: {score}")


def _bounty_value(bounty_range: dict[str, Any]) -> float:
    minimum = bounty_range.get("minBounty")
    if not isinstance(minimum, dict):
        return 0.0
    value = minimum.get("value", 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def parse_tiers(program: dict[str, Any]) -> dict[int, dict[str, Any]]:
    content = _latest_snapshot(program, "bountyTables")
    rows = content.get("bountyRows")
    if not isinstance(rows, list):
        raise ValueError("latest bounty table has no bounty rows")

    tiers: dict[int, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        tier_id = row.get("bountyTierId")
        ranges = row.get("bountyRanges")
        if isinstance(tier_id, bool) or not isinstance(tier_id, int) or not isinstance(ranges, list):
            continue
        paid_floors = [
            float(item["minScore"])
            for item in ranges
            if isinstance(item, dict)
            and isinstance(item.get("minScore"), (int, float))
            and not isinstance(item.get("minScore"), bool)
            and _bounty_value(item) > 0
        ]
        if not paid_floors:
            continue
        floor = min(paid_floors)
        tiers[tier_id] = {"min_score": floor, "report_floor": _severity_label(floor)}

    if not tiers:
        raise ValueError("program has no paying tier; refusing to create an empty engagement")
    return tiers


def _normalize_asset_target(asset_type: int, name: str) -> str:
    if asset_type == 1:
        return extract_host(name)
    if asset_type == 7:
        kind, suffix = normalize_pattern(name)
        if kind != "wildcard":
            raise ValueError(f"wildcard asset is not a wildcard hostname: {name}")
        return f"*.{suffix}"
    if name.startswith("*."):
        kind, suffix = normalize_pattern(name)
        if kind != "wildcard":
            raise ValueError(f"cannot normalize unknown asset as target: {name}")
        return f"*.{suffix}"
    return extract_host(name)


def _unknown_asset_action(name: str, type_id: Any, input_func: Callable[[str], str]) -> str:
    answer = input_func(
        f"Unknown Intigriti asset typeId {type_id!r} for {name!r}. "
        "Put in [N]otes, include as [T]arget, or [S]kip? [N]: "
    ).strip().lower()
    choices = {"": "notes", "n": "notes", "notes": "notes", "t": "target", "target": "target", "s": "skip", "skip": "skip"}
    if answer not in choices:
        raise ValueError(f"invalid unknown-asset choice: {answer!r}")
    return choices[answer]


def parse_scope(
    program: dict[str, Any],
    tiers: dict[int, dict[str, Any]],
    *,
    assume_yes: bool = False,
    input_func: Callable[[str], str] = input,
) -> dict[str, Any]:
    content = _latest_snapshot(program, "assetsCollection")
    assets = content.get("assetsAndGroups")
    if not isinstance(assets, list):
        raise ValueError("latest assets snapshot has no assetsAndGroups")

    targets: list[str] = []
    tier_patterns: dict[int, list[str]] = {tier_id: [] for tier_id in tiers}
    non_web: list[str] = []
    unknown_notes: list[str] = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        tier_id = asset.get("bountyTierId")
        if tier_id not in tiers:
            continue
        name = str(asset.get("name") or "").strip()
        type_id = asset.get("typeId")
        if not name:
            continue
        if type_id in (1, 7):
            target = _normalize_asset_target(type_id, name)
            if target not in targets:
                targets.append(target)
            if target not in tier_patterns[tier_id]:
                tier_patterns[tier_id].append(target)
            continue
        if type_id in NON_WEB_TYPES:
            label = NON_WEB_TYPES[type_id]
            description = str(asset.get("description") or "").strip()
            suffix = f" — {description}" if description else ""
            non_web.append(f"{label}: {name}{suffix}")
            continue

        action = "notes" if assume_yes else _unknown_asset_action(name, type_id, input_func)
        if action == "target":
            target = _normalize_asset_target(-1, name)
            if target not in targets:
                targets.append(target)
            if target not in tier_patterns[tier_id]:
                tier_patterns[tier_id].append(target)
        elif action == "notes":
            unknown_notes.append(f"Unknown typeId {type_id}: {name}")

    if not targets:
        raise ValueError("paying tiers contain no web targets")
    return {
        "targets": targets,
        "tier_patterns": tier_patterns,
        "non_web": non_web,
        "unknown_notes": unknown_notes,
    }


def _latest_structured_roe(program: dict[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    snapshots = program.get("rulesOfEngagements")
    if not isinstance(snapshots, list):
        raise ValueError("program has no rulesOfEngagements snapshots")
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        wrapper = snapshot.get("content")
        inner = wrapper.get("content") if isinstance(wrapper, dict) else None
        if not isinstance(inner, dict) or not isinstance(inner.get("testingRequirements"), dict):
            continue
        copy = dict(inner)
        created_at = inner.get("createdAt", snapshot.get("createdAt", 0))
        copy["_selection_created_at"] = created_at if isinstance(created_at, (int, float)) else 0
        candidates.append(copy)
    if not candidates:
        raise ValueError("program has no structured rules of engagement with testing requirements")
    return max(candidates, key=lambda item: item["_selection_created_at"])


def _snapshot_markdown(program: dict[str, Any], key: str) -> str:
    content = _latest_snapshot(program, key).get("content")
    return content if isinstance(content, str) else ""


def _choose_rate_limit(values: list[int], input_func: Callable[[str], str]) -> int:
    strictest = min(values)
    choices = ", ".join(str(item) for item in sorted(set(values)))
    answer = input_func(
        f"Rate-limit conflict ({choices} requests/sec). "
        f"Use the stricter {strictest} requests/sec? [Y/n, or enter listed value]: "
    ).strip().lower()
    if answer in {"", "y", "yes"}:
        return strictest
    if answer in {"n", "no"}:
        return max(values)
    try:
        selected = int(answer)
    except ValueError as exc:
        raise ValueError(f"invalid rate-limit choice: {answer!r}") from exc
    if selected not in values:
        raise ValueError(f"rate-limit choice must be one of: {choices}")
    return selected


def _required_headers(requirements: dict[str, Any], username: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    request_header = requirements.get("requestHeader")
    if isinstance(request_header, str) and request_header.strip():
        if ":" not in request_header:
            raise ValueError("requestHeader must use 'Name: value' format")
        name, value = (part.strip() for part in request_header.split(":", 1))
        value = USERNAME_PLACEHOLDER_RE.sub(username, value)
        if not name or not value:
            raise ValueError("requestHeader must contain a non-empty name and value")
        headers[name] = value
    user_agent = requirements.get("userAgent")
    if isinstance(user_agent, str) and user_agent.strip():
        headers["User-Agent"] = USERNAME_PLACEHOLDER_RE.sub(username, user_agent.strip())
    return headers


def parse_roe(
    program: dict[str, Any],
    username: str,
    *,
    assume_yes: bool = False,
    input_func: Callable[[str], str] = input,
) -> dict[str, Any]:
    structured = _latest_structured_roe(program)
    requirements = structured["testingRequirements"]
    automated = requirements.get("automatedTooling")
    structured_rate = (
        int(automated)
        if isinstance(automated, int) and not isinstance(automated, bool) and automated > 0
        else None
    )
    prose = "\n\n".join(
        filter(
            None,
            (
                str(program.get("description") or ""),
                _snapshot_markdown(program, "inScopes"),
                _snapshot_markdown(program, "outOfScopes"),
                str(structured.get("description") or ""),
            ),
        )
    )
    prose_rates = [int(match.group(1)) for match in RATE_RE.finditer(prose) if int(match.group(1)) > 0]
    rate_values = ([structured_rate] if structured_rate is not None else []) + prose_rates
    unique_rates = sorted(set(rate_values))
    if len(unique_rates) > 1 and not assume_yes:
        rate_limit = _choose_rate_limit(unique_rates, input_func)
    else:
        rate_limit = min(unique_rates) if unique_rates else None
    return {
        "rate_limit": rate_limit,
        "required_headers": _required_headers(requirements, username),
        "intigriti_me": requirements.get("intigritiMe") is True,
        "safe_harbour": structured.get("safeHarbour") is True,
        "description": str(structured.get("description") or "").strip(),
        "scanner_prohibited": bool(re.search(r"automatic scanners?|automated scans?", prose, re.IGNORECASE)),
    }


def _employee_account_prose(program: dict[str, Any]) -> str:
    blocks: list[str] = []
    in_scope = _snapshot_markdown(program, "inScopes")
    heading = re.search(r"(?im)^#{1,6}\s+Employee user accounts\s*$", in_scope)
    if heading:
        section = in_scope[heading.start() :]
        next_heading = re.search(r"(?im)^#{1,6}\s+", section[heading.end() - heading.start() :])
        if next_heading:
            section = section[: heading.end() - heading.start() + next_heading.start()]
        blocks.append(section.strip())

    assets = _latest_snapshot(program, "assetsCollection").get("assetsAndGroups")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict) or asset.get("typeId") != 6:
                continue
            text = "\n".join(str(asset.get(key) or "") for key in ("name", "description")).strip()
            if re.search(r"\baccounts?\b", text, re.IGNORECASE):
                blocks.append(text)
    return "\n\n".join(dict.fromkeys(blocks))


def _prose_domain_carveouts(account_prose: str, targets: list[str]) -> list[str]:
    candidates: list[str] = []
    for match in DOMAIN_RE.finditer(account_prose):
        candidate = match.group(0).lower().rstrip(".")
        if candidate in targets:
            continue
        exact = candidate[2:] if candidate.startswith("*.") else candidate
        if any(pattern_matches(exact, target) for target in targets):
            continue
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _confirm_domain_carveouts(candidates: list[str], input_func: Callable[[str], str]) -> list[str]:
    answer = input_func(
        "Add prose-only domain/account carve-outs to out_of_scope "
        f"({', '.join(candidates)})? [Y/n]: "
    ).strip().lower()
    if answer in {"", "y", "yes"}:
        return candidates
    if answer in {"n", "no"}:
        return []
    raise ValueError(f"invalid out-of-scope choice: {answer!r}")


def _key_objectives(in_scope: str) -> list[str]:
    marker = re.search(r"(?im)^\*\*Key objectives\*\*\s*:\s*$", in_scope)
    if not marker:
        return []
    objectives: list[str] = []
    for line in in_scope[marker.end() :].splitlines():
        stripped = line.strip()
        if not stripped:
            if objectives:
                break
            continue
        bullet = re.match(r"^[*-]\s+(.+)$", stripped)
        if not bullet:
            if objectives:
                break
            continue
        objectives.append(bullet.group(1).strip())
    return objectives


def _tier_objective(tier_name: str, floor: str, patterns: list[str]) -> str:
    joined = ", ".join(patterns)
    if floor == "low":
        return f"{tier_name}: test the full Low-to-Exceptional severity range on {joined}"
    return f"{tier_name}: report only {floor.title()}-or-higher findings on {joined}"


def _build_notes(
    program: dict[str, Any],
    scope: dict[str, Any],
    roe: dict[str, Any],
    account_prose: str,
) -> str:
    name = str(program.get("name") or program.get("handle") or "unknown")
    sections = [f'Program: Intigriti public "{name}".']
    if roe["safe_harbour"]:
        sections[0] += " Safe harbour applies."
    requirements: list[str] = []
    for header, value in roe["required_headers"].items():
        requirements.append(f"- Mandatory request header: {header}: {value}")
    if roe["rate_limit"] is not None:
        requirements.append(f"- Automated tooling rate cap: {roe['rate_limit']} requests/second")
    if roe["scanner_prohibited"]:
        requirements.append("- Automatic vulnerability scanners are prohibited; use targeted, low-load testing")
    if roe["intigriti_me"]:
        requirements.append("- Test accounts must be registered with an @intigriti.me email address")
    if requirements:
        sections.append("Mandatory testing requirements:\n" + "\n".join(requirements))
    if account_prose:
        sections.append("Domain/account carve-outs from program prose:\n" + account_prose)
    if scope["non_web"]:
        sections.append("In-scope non-web assets (not emitted as web targets):\n" + "\n".join(f"- {item}" for item in scope["non_web"]))
    if scope["unknown_notes"]:
        sections.append("Unknown asset types kept out of web targets:\n" + "\n".join(f"- {item}" for item in scope["unknown_notes"]))
    out_of_scope = _snapshot_markdown(program, "outOfScopes").strip()
    if out_of_scope:
        sections.append("Non-qualifying / out-of-scope vulnerability classes (verbatim from Intigriti):\n" + out_of_scope)
    return ("\n\n".join(sections).strip() + "\n").expandtabs(2)


def build_yaml(
    program: dict[str, Any],
    username: str,
    *,
    assume_yes: bool = False,
    input_func: Callable[[str], str] = input,
) -> dict[str, Any]:
    tiers = parse_tiers(program)
    scope = parse_scope(program, tiers, assume_yes=assume_yes, input_func=input_func)
    roe = parse_roe(program, username, assume_yes=assume_yes, input_func=input_func)
    account_prose = _employee_account_prose(program)
    candidates = _prose_domain_carveouts(account_prose, scope["targets"])
    out_of_scope = (
        candidates
        if assume_yes or not candidates
        else _confirm_domain_carveouts(candidates, input_func)
    )

    yaml_tiers: dict[str, dict[str, Any]] = {}
    objectives = _key_objectives(_snapshot_markdown(program, "inScopes"))
    for tier_id, tier in tiers.items():
        patterns = scope["tier_patterns"].get(tier_id, [])
        if not patterns:
            continue
        tier_name = f"tier_{tier_id}"
        yaml_tiers[tier_name] = {
            "report_floor": tier["report_floor"],
            "patterns": patterns,
        }
        objectives.append(_tier_objective(tier_name, tier["report_floor"], patterns))

    program_name = str(program.get("name") or program.get("handle") or "Intigriti program")
    description = str(program.get("description") or "").strip()
    intent = f"Authorized black-box web and API security testing of {program_name} under its public Intigriti program."
    if roe["safe_harbour"]:
        intent += " Safe harbour applies."
    if description:
        intent += f" Program context: {description}"

    generated: dict[str, Any] = {
        "name": str(program.get("handle") or "").strip(),
        "targets": scope["targets"],
        "out_of_scope": out_of_scope,
        "egress_support": [],
        "tiers": yaml_tiers,
        "source_path": None,
        "source_ref": None,
        "audit_include": [],
        "audit_exclude": ["node_modules", "vendor", "dist", ".git"],
        "intent": intent,
        "objectives": objectives,
    }
    for gate in ROE_GATES:
        generated[gate] = False
    rate_limit = roe["rate_limit"]
    generated["rate_limit_enabled"] = rate_limit is not None
    if rate_limit is not None:
        generated["rate_limit"] = {
            "requests_per_second": rate_limit,
            "burst": rate_limit,
            "max_concurrency": 2,
            "per_tool": {
                tool: {"requests_per_second": 2, "burst": 2, "max_concurrency": 1}
                for tool in ("nuclei", "ffuf", "schemathesis")
            },
        }
    generated.update(
        {
            "max_threads": 2,
            "time_window": "any",
            "retention": {"status": "active", "owner": username, "expires_at": ""},
            "required_headers": roe["required_headers"],
            "oob_host": "",
            "test_credentials": [],
            "notes": _build_notes(program, scope, roe, account_prose),
        }
    )
    return generated


def render_yaml(generated: dict[str, Any]) -> str:
    return yaml.dump(generated, Dumper=DraftDumper, sort_keys=False, allow_unicode=True)


def fetch_program(company: str, program: str) -> dict[str, Any]:
    url = (
        "https://app.intigriti.com/api/core/public/programs/"
        f"{quote(company, safe='')}/{quote(program, safe='')}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "web-pentest-harness-intigriti-parser/1"})
    try:
        # URL origin and scheme are fixed above; only validated handles are interpolated.
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            payload = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise ValueError(
                "program is not public (needs authentication) — this tool handles public programs only"
            ) from exc
        raise ValueError(f"Intigriti API returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"cannot fetch Intigriti program: {exc.reason}") from exc
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Intigriti API returned a non-JSON response") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Intigriti API returned an invalid program document")
    return parsed


def _load_program_file(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read JSON fixture {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"saved program is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("saved program JSON root must be an object")
    return parsed


def _validate_rendered(rendered: str) -> None:
    with tempfile.TemporaryDirectory(prefix="intigriti-draft-") as temp_dir:
        candidate = Path(temp_dir) / "engagement.yaml"
        candidate.write_text(rendered, encoding="utf-8")
        load_engagement(candidate)


def _write_draft(output: Path, rendered: str, *, force: bool) -> None:
    if output.exists() and not force:
        raise ValueError(f"{output} already exists; pass --force to overwrite it")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", help="Intigriti program URL or company/program slug")
    parser.add_argument("--username", required=True, help="Intigriti username for required header templates")
    parser.add_argument("--out", type=Path, help="output directory (default: engagements/<handle>/)")
    parser.add_argument("--from-file", type=Path, metavar="JSON", help="parse saved public program JSON")
    parser.add_argument("--yes", action="store_true", help="accept safe defaults without prompting")
    parser.add_argument("--force", action="store_true", help="overwrite an existing engagement.yaml")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        company, program_handle = parse_program_ref(args.program)
        program = _load_program_file(args.from_file) if args.from_file else fetch_program(company, program_handle)
        generated = build_yaml(program, args.username, assume_yes=args.yes)
        rendered = render_yaml(generated)
        _validate_rendered(rendered)
        handle = generated["name"] or program_handle
        out_dir = args.out if args.out is not None else ROOT / "engagements" / handle
        output = out_dir / "engagement.yaml"
        _write_draft(output, rendered, force=args.force)
    except (ValueError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Draft engagement written: {output}")
    print(
        f"Summary: {len(generated['targets'])} web targets, "
        f"{len(generated['tiers'])} paying tiers, "
        f"{len(generated['out_of_scope'])} explicit carve-outs."
    )
    print("Review the draft before activation; .active_engagement was not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
