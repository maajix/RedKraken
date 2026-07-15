---
description: Run the full autonomous whitebox source-code audit for an engagement (map → triage → audit → confirm → report).
argument-hint: <engagement-dir>  e.g. engagements/acme
---

Run a fully-autonomous whitebox source-code security audit for engagement: **$ARGUMENTS**

**Load and follow the `code-audit-loop` skill** and execute every phase end to end. Also obey `scope-guard` and `tool-preflight` throughout.

Setup before you start:
1. Resolve the engagement dir from `$ARGUMENTS`.
   - If it's empty, or there's no `engagement.yaml`, **stop**: tell the operator to create `engagements/<name>/engagement.yaml` from `scope/engagement.example.yaml` and set `source_path` (+ authorization to audit).
2. Require `<dir>/engagement.yaml`. Read `source_path`, `audit_include`/`audit_exclude`, `intent`, RoE, and any optional `targets`/`out_of_scope`. If `source_path` is empty or authorization is unclear → **stop and ask the operator** (no source + authorization, no audit).
3. Initialize or verify the immutable run context:
   ```bash
   python3 lib/run_context.py "<dir>" --mode audit
   mkdir -p "<dir>"/state/scan-raw
   bash lib/code_preflight.sh
   ```
   `STALE_RUN_CONTEXT` is a hard stop: archive the prior state before starting a new run.
   Surface any missing scanners to the operator (they're optional — the audit still runs on the LLM auditor + ripgrep sink packs; missing scanners become per-family coverage gaps). If **core** tools (`rg`/`jq`) are missing, stop.
4. Then proceed through map → triage → audit (parallel family auditors) → confirm (variant analysis + grey-box if in-scope `targets` exist) → report, exactly as the `code-audit-loop` skill specifies, dispatching the sub-agents and keeping `state/` + `audit.jsonl` + `evidence/` current.

End by reporting the `report.md` path and a summary: counts by severity, confirmed vs suspected, notable chains, and scanner-coverage gaps.
