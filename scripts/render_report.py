#!/usr/bin/env python3
"""Deterministically render report.md from engagement state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from harness_config import ConfigError, engagement_yaml, load_engagement, roe_authorizations  # noqa: E402
from secure_engagement import secure_engagement  # noqa: E402


SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
OMIT_MAIN = {"not-tested", "not-exploitable"}


def md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def load_findings(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid findings line {number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"findings line {number} is not an object")
        missing = [field for field in ("id", "technique", "severity", "status") if not row.get(field)]
        if missing:
            warnings.append(f"line {number} missing {', '.join(missing)}")
        rows.append(row)
    rows.sort(key=lambda row: (SEVERITY.get(str(row.get("severity", "info")).lower(), 99), str(row.get("id", ""))))
    return rows, warnings


def evidence_lines(directory: Path, row: dict[str, Any]) -> tuple[list[str], list[str]]:
    output: list[str] = []
    warnings: list[str] = []
    root = directory.resolve()
    for relative in row.get("evidence") or []:
        path = (directory / str(relative)).resolve()
        if root not in path.parents:
            warnings.append(f"{row.get('id')}: evidence path escapes engagement: {relative}")
            continue
        if not path.is_file():
            output.append(f"- `{md(relative)}` (missing)")
            warnings.append(f"{row.get('id')}: evidence missing: {relative}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        output.append(f"- `{md(relative)}` (`sha256:{digest}`)")
    if not output:
        output.append("- Evidence pending")
        warnings.append(f"{row.get('id')}: no evidence paths")
    return output, warnings


CODE_LANG = {
    ".ts": "ts", ".tsx": "tsx", ".js": "js", ".jsx": "jsx", ".py": "python",
    ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java", ".sql": "sql",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json",
}


def code_lang(file: Any) -> str:
    return CODE_LANG.get(Path(str(file or "")).suffix.lower(), "text")


def affected(row: dict[str, Any]) -> str:
    if row.get("endpoint"):
        suffix = f" parameter `{md(row.get('param'))}`" if row.get("param") else ""
        return f"`{md(row.get('method') or 'GET')} {md(row['endpoint'])}`{suffix}"
    if row.get("file"):
        return f"`{md(row['file'])}:{md(row.get('line'))}`"
    if row.get("component"):
        return f"`{md(row['component'])}`"
    return "Not recorded"


def audit_summary(directory: Path) -> list[str]:
    path = directory / "audit.jsonl"
    if not path.is_file():
        legacy = directory / "audit.log"
        return [f"Legacy audit rows: {len(legacy.read_text(errors='replace').splitlines())}"] if legacy.is_file() else ["No command audit available."]
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    tools = Counter(str(event.get("tool") or event.get("phase") or event.get("event") or "unknown") for event in events)
    return [f"Structured audit events: {len(events)}.", "By tool/phase: " + ", ".join(f"{key}={value}" for key, value in sorted(tools.items())) + "."]


def background_section(directory: Path) -> list[str]:
    notes = directory / "state" / "notes.md"
    text = notes.read_text(encoding="utf-8").strip() if notes.exists() else ""
    return ["## Background & Environment", "", text, ""] if text else []


def render(directory: Path, config: dict[str, Any], rows: list[dict[str, Any]], input_warnings: list[str]) -> str:
    counts = Counter(str(row.get("severity", "info")).lower() for row in rows if row.get("status") not in OMIT_MAIN)
    roe = roe_authorizations(config)
    lines = [
        f"# Web Application Penetration Test - {md(config.get('name') or directory.name)}",
        "",
        "## Executive Summary",
        "",
        f"Recorded findings: {len(rows)}. " + ", ".join(f"{name.title()}: {counts.get(name, 0)}" for name in SEVERITY) + ".",
        "",
        "## Scope & Rules of Engagement",
        "",
        f"- Targets: {', '.join(f'`{md(item)}`' for item in config.get('targets') or []) or 'None (white-box only)'}",
        f"- Out of scope: {', '.join(f'`{md(item)}`' for item in config.get('out_of_scope') or []) or 'None listed'}",
        f"- Mutation allowed: `{str(roe['mutation_allowed']).lower()}`",
        f"- Sensitive data access allowed: `{str(roe['sensitive_data_access_allowed']).lower()}`",
        f"- Credential use allowed: `{str(roe['credential_use_allowed']).lower()}`",
        f"- Pivoting allowed: `{str(roe['pivoting_allowed']).lower()}`",
        f"- Availability impact allowed: `{str(roe['availability_impact_allowed']).lower()}`",
        f"- Time window: `{md(config.get('time_window') or 'any')}`",
        "",
        *background_section(directory),
        "## Methodology",
        "",
        "Scope-gated recon -> structured triage -> family testing -> evidence-backed confirmation -> deterministic reporting.",
        "",
        "## Findings",
        "",
    ]
    report_warnings = list(input_warnings)
    main_rows = [row for row in rows if row.get("status") not in OMIT_MAIN]
    if not main_rows:
        lines.extend(["No confirmed or suspected findings were recorded.", ""])
    for row in main_rows:
        severity = str(row.get("severity", "info")).upper()
        title = row.get("title") or row.get("technique") or row.get("id") or "Finding"
        lines.extend([
            f"### [{severity}] {md(title)}",
            "",
            f"**TL;DR:** {md(row.get('summary') or 'Summary not recorded.')}",
            "",
            "---",
            "",
            "#### Summary",
            "",
            md(row.get("description") or row.get("summary") or "Summary not recorded."),
            "",
            "#### Details",
            "",
            f"- ID: `{md(row.get('id'))}`",
            f"- Affected: {affected(row)}",
            f"- Status: `{md(row.get('status'))}`",
            f"- Source: `{md(row.get('source') or 'unknown')}`",
            f"- CWE: `{md(row.get('cwe') or 'not mapped')}`",
            "",
        ])
        if row.get("dataflow"):
            lines.extend(f"{index}. {md(step)}" for index, step in enumerate(row["dataflow"], 1))
            lines.append("")
        if row.get("code_excerpt"):
            lines.extend([f"```{code_lang(row.get('file'))}", str(row["code_excerpt"]), "```", ""])
        lines.extend(["#### PoC", "", "```text"])
        lines.extend(md(step) for step in (row.get("repro") or ["Not recorded"]))
        lines.extend(["```", ""])
        lines.extend(["#### Evidence", ""])
        evidence, warnings = evidence_lines(directory, row)
        lines.extend(evidence)
        report_warnings.extend(warnings)
        lines.extend([
            "",
            "#### Impact",
            "",
            md(row.get("impact") or "Impact not yet recorded."),
            "",
            "#### Recommended Fix",
            "",
            md(row.get("remediation") or "Remediation not yet recorded."),
            "",
        ])
    lines.extend(["## Coverage & Limitations", ""])
    coverage = [row for row in rows if row.get("status") in OMIT_MAIN]
    if coverage:
        lines.extend(["| Technique | Status | Reason |", "|---|---|---|"])
        for row in coverage:
            lines.append(f"| {md(row.get('technique'))} | {md(row.get('status'))} | {md(row.get('status_reason') or row.get('summary'))} |")
    else:
        lines.append("No machine-readable not-tested or not-exploitable coverage rows were recorded.")
    if report_warnings:
        lines.extend(["", "### Data Quality Warnings", ""])
        lines.extend(f"- {md(warning)}" for warning in sorted(set(report_warnings)))
    lines.extend(["", "## Appendix: Command Audit", ""])
    lines.extend(audit_summary(directory))
    lines.append("")
    return "\n".join(lines)


def atomic_write(path: Path, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".report.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engagement")
    args = parser.parse_args()
    try:
        yaml_path = engagement_yaml(args.engagement)
        directory = yaml_path.parent
        secure_engagement(directory)
        findings = directory / "state/findings.jsonl"
        if not findings.is_file():
            raise ValueError(f"findings file missing: {findings}")
        rows, warnings = load_findings(findings)
        output = directory / "report.md"
        atomic_write(output, render(directory, load_engagement(yaml_path), rows, warnings))
        secure_engagement(directory)
        print(output)
        return 0
    except (ConfigError, OSError, ValueError) as exc:
        print(f"render_report: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
