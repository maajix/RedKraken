#!/usr/bin/env python3
"""Fail closed when the reviewed topic playbook catalog drifts.

This is intentionally dependency-free: it validates the small front-matter
subset used by the repository rather than accepting arbitrary YAML.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"
FAMILIES = ROOT / ".claude" / "skills" / "families"
CATALOG = PLAYBOOKS / "_catalog.md"
BASELINES = PLAYBOOKS / "_meta" / "coverage-baselines.json"
REQUIRED = {
    "id",
    "title",
    "family",
    "review_status",
    "reviewed_at",
    "destructive_risk",
}
REQUIRED_SECTIONS = {
    "Safe detection",
    "Confirmation and evidence",
    "Remediation",
    "Sources",
}


def front_matter(text: str, path: Path) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing front matter")
    try:
        raw, _body = text[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise ValueError(f"{path}: unterminated front matter") from exc
    values: dict[str, str] = {}
    for lineno, line in enumerate(raw.splitlines(), 2):
        if not line or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"{path}:{lineno}: invalid front-matter line")
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip().strip('"\'')
        if not key or not value or key in values:
            raise ValueError(f"{path}:{lineno}: empty or duplicate field {key!r}")
        values[key] = value
    return values


def main() -> int:
    errors: list[str] = []
    playbooks = sorted(
        path
        for path in PLAYBOOKS.glob("*/README.md")
        if path.parent.name != "code-review"
    )
    family_dirs = {p.name for p in FAMILIES.iterdir() if (p / "SKILL.md").is_file()}
    ids: Counter[str] = Counter()
    reviewed_families: set[str] = set()

    for path in playbooks:
        text = path.read_text(encoding="utf-8")
        try:
            meta = front_matter(text, path.relative_to(ROOT))
        except ValueError as exc:
            errors.append(str(exc))
            continue
        missing = sorted(REQUIRED - meta.keys())
        if missing:
            errors.append(f"{path.relative_to(ROOT)}: missing fields {', '.join(missing)}")
        ids[meta.get("id", "<missing>")] += 1
        if meta.get("review_status") != "source-reviewed":
            errors.append(f"{path.relative_to(ROOT)}: review_status must be source-reviewed")
        if meta.get("destructive_risk") not in {"low", "medium", "high"}:
            errors.append(f"{path.relative_to(ROOT)}: invalid destructive_risk")
        try:
            dt.date.fromisoformat(meta.get("reviewed_at", ""))
        except ValueError:
            errors.append(f"{path.relative_to(ROOT)}: reviewed_at must be YYYY-MM-DD")
        if meta.get("family") not in family_dirs:
            errors.append(
                f"{path.relative_to(ROOT)}: family {meta.get('family')!r} has no family skill"
            )
        else:
            reviewed_families.add(meta["family"])

        sections = set(re.findall(r"(?m)^## (.+?)\s*$", text))
        missing_sections = sorted(REQUIRED_SECTIONS - sections)
        if missing_sections:
            errors.append(
                f"{path.relative_to(ROOT)}: missing sections {', '.join(missing_sections)}"
            )
        sources = text.split("\n## Sources\n", 1)[-1]
        source_links = re.findall(r"\[[^]]+\]\((https://[^)]+)\)", sources)
        if len(source_links) < 2:
            errors.append(f"{path.relative_to(ROOT)}: fewer than two HTTPS primary sources")

    for playbook_id, count in ids.items():
        if count != 1:
            errors.append(f"duplicate playbook id {playbook_id!r}: {count}")

    catalog_text = CATALOG.read_text(encoding="utf-8")
    expected_paths = {path.relative_to(PLAYBOOKS).as_posix() for path in playbooks}
    catalog_paths = set(re.findall(r"`([^`]+/README\.md)`", catalog_text))
    for path in sorted(expected_paths - catalog_paths):
        errors.append(f"playbooks/{path}: missing from _catalog.md")
    for path in sorted(catalog_paths - expected_paths - {"code-review/README.md"}):
        errors.append(f"playbooks/_catalog.md: unknown topic entrypoint {path}")

    card_ids = {
        front_matter(path.read_text(encoding="utf-8"), path.relative_to(ROOT))["id"]
        .removeprefix("modern-") + ".md": path
        for path in playbooks
    }

    loop_text = (ROOT / ".claude" / "skills" / "web-pentest-loop" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    hunter_text = (ROOT / ".claude" / "agents" / "web-vuln-hunter.md").read_text(
        encoding="utf-8"
    )
    for family in sorted(reviewed_families):
        skill_path = FAMILIES / family / "SKILL.md"
        try:
            skill_name = front_matter(skill_path.read_text(encoding="utf-8"), skill_path)["name"]
        except (ValueError, KeyError) as exc:
            errors.append(f"{skill_path.relative_to(ROOT)}: invalid skill name: {exc}")
            continue
        if family not in loop_text:
            errors.append(f"web-pentest-loop: family {family!r} is not routable")
        if skill_name not in hunter_text:
            errors.append(f"web-vuln-hunter: skill {skill_name!r} is not loadable")

    try:
        manifest = json.loads(BASELINES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{BASELINES.relative_to(ROOT)}: invalid JSON: {exc}")
        manifest = {"baselines": []}
    baseline_ids: Counter[str] = Counter()
    for baseline in manifest.get("baselines", []):
        baseline_id = baseline.get("id", "<missing>")
        baseline_ids[baseline_id] += 1
        if baseline.get("status") not in {"stable", "developing", "draft"}:
            errors.append(f"coverage baseline {baseline_id}: invalid source status")
        if not str(baseline.get("source", "")).startswith("https://"):
            errors.append(f"coverage baseline {baseline_id}: source must be HTTPS")
        required = baseline.get("required_controls", [])
        controls = baseline.get("controls", {})
        if len(required) != len(set(required)) or set(required) != set(controls):
            errors.append(f"coverage baseline {baseline_id}: required_controls and controls differ")
        for control_id, control in controls.items():
            refs = control.get("playbooks", [])
            if not control.get("name") or not refs:
                errors.append(f"coverage baseline {baseline_id}/{control_id}: empty name/playbooks")
            for ref in refs:
                if ref not in card_ids:
                    errors.append(
                        f"coverage baseline {baseline_id}/{control_id}: unknown playbook {ref}"
                    )
    for baseline_id, count in baseline_ids.items():
        if count != 1:
            errors.append(f"duplicate coverage baseline id {baseline_id!r}: {count}")

    print(
        f"reviewed_topics={len(playbooks)} catalog_topics={len(expected_paths & catalog_paths)} "
        f"families={len(reviewed_families)} baselines={len(baseline_ids)} "
        f"errors={len(errors)}"
    )
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: topic playbook metadata, sources, family skills, and catalog agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
