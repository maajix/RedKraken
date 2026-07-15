---
name: code-audit-loop
description: The master methodology for running a fully-autonomous whitebox source-code security audit end to end — intake, code mapping, triage, per-family source→sink auditing, confirmation (variant analysis + grey-box), and reporting — reusing the harness safety/findings/reporting machinery while staying in authorization. Use when running /audit or orchestrating a code audit.
---

# Code Audit Loop (whitebox orchestrator)

You are the orchestrator for a whitebox engagement. You run a closed loop over
ONE engagement's source tree and dispatch sub-agents for the heavy phases. This
is the whitebox sibling of `web-pentest-loop` — same discipline, same
`findings.jsonl`, same `reporter`. Every phase obeys `scope-guard`
(authorization) and `tool-preflight` (notify on missing tools — never silently
skip).

`$HARNESS` = repo root (contains `lib/`, `playbooks/`, `.claude/`).

## Non-negotiables
- **In authorization or not at all.** Require `source_path` + authorization to
  audit. Ambiguous → **STOP and ask the operator.**
- **Audit everything** that runs a tool. Claude hooks write structured events to `audit.jsonl`; use `lib/audit.sh` only outside Claude Code.
- **A finding is `confirmed` only with a traced source→sink path and real
  `file:line` you actually read.** No traced path ⇒ `suspected`. Never invent
  line numbers. (This is the anti-hallucination guardrail — enforce it.)
- **Two lead types** (see `playbooks/code/_catalog.md`):
  - *Trace families* (injection, client-side, ssrf-xxe-file, deserialization,
    auth-session, http-protocol, access-control): scanner/grep hits are leads →
    the auditor must trace before confirming.
  - *Scanner-native families* (supply-chain, secrets-crypto secrets, config-iac):
    the scanner output **is** the finding — dedupe/validate/reachability-check,
    then record directly (`source: sca:<tool>`/`secret:<tool>`/`iac:<tool>`).
- **Notify on tool gaps**; record the family a missing scanner would have covered
  as a coverage gap, don't drop it silently.

## Shared environment facts — `state/notes.md`

You (the orchestrator) are the sole writer. As each sub-agent returns its summary, distil durable, security-relevant *non-vulnerability* facts into `state/notes.md`: stack & versions, auth/session model, tenancy/isolation model, observed defenses (rate-limit/WAF/CSP), and *locations* of obtained credentials/tokens — never the raw secret, reference the evidence/state file. Keep it tight and factual; it is not a scratchpad or lead tracker (leads → `worklist.json` + `suspected` findings). It feeds the report Background section and lets a resumed run skip rediscovery.

## Phase 0 — Intake & authorization gate
1. Engagement dir = command argument (e.g. `engagements/acme`). Require `engagement.yaml`.
2. Read `source_path`, `audit_include/exclude`, `intent`, RoE, and (optional) `targets`/`out_of_scope`. If `source_path` empty or authorization unclear → **stop and ask.**
3. Initialize or verify:
   ```bash
   python3 "$HARNESS/lib/run_context.py" "$PWD/engagements/acme" --mode audit
   export PENTEST_ENGAGEMENT_DIR="$PWD/engagements/acme"
   mkdir -p "$PENTEST_ENGAGEMENT_DIR"/state/scan-raw
   ```
   `STALE_RUN_CONTEXT` is a hard stop until prior state is archived.
4. `bash "$HARNESS/lib/code_preflight.sh"`. Core (`rg`/`jq`) missing → notify and stop. Scanners missing → note as coverage gaps (audit still runs on the auditor + ripgrep sink packs).
5. Init `state/loop.json` (`phase: map`). If it exists you are **resuming** — read it and continue from `phase`.

## Phase 1 — Map (code-recon)
Dispatch the **`code-mapper`** agent (Task tool) with the engagement dir. It follows `code-recon` and writes `state/codemap.json` + `state/scan-raw/*`. Wait for its summary and fold its environment facts (languages/frameworks, entry-point auth, dependency manifests) into `state/notes.md`. Update `loop.json` → `phase: triage`.

## Phase 2 — Triage (you, the orchestrator)
1. Read `state/codemap.json` and every file under `state/scan-raw/` (parse SARIF/JSON with `jq`), plus `playbooks/code/_catalog.md`.
2. **Normalize + dedup** scanner leads → `{family, file, line, rule, severity, tool}`. Route each to a family via the catalog. Dedup on `family+file+line+rule`.
3. Split by lead type:
   - *Scanner-native* leads (supply-chain/secrets/config-iac) → stage them as `suspected` rows for the matching family auditor to validate and record.
   - *Trace-family* leads + the codemap entry points → `state/worklist.json` (family → [{file, line, sink, why}]). Prioritise unguarded entry points (from codemap `auth: none`) and high-severity sinks. Use `intent`/`objectives` to weight.
4. Write `state/worklist.json`. Update `loop.json` → `phase: audit`.

## Phase 3 — Audit (the closed loop)
For each family with work, dispatch a **`code-auditor`** (Task tool) with the engagement dir + family + its worklist slice. Families are independent → dispatch them **in parallel** (multiple Task calls in one message).

Each auditor runs analyse→trace→confirm per candidate:
> open the family's `playbooks/code/sinks-<lang>.md`, matching family skill, and
> source-reviewed modern card → run the ripgrep sweep for its sinks → **read the
> code and trace back to a request-controlled source** → confirm (reachable
> source→sink, no sanitizer) / reject / mark suspected → capture the `file:line`
> data-flow path + code excerpt as evidence → record it in `findings.jsonl`.

For scanner-native families the auditor validates the staged scanner rows (drop false positives, check reachability where possible) and records them. As each auditor returns, fold its **Environment facts** into `state/notes.md` and update `loop.json.families_done`.

### findings.jsonl (one JSON object per line — shared with blackbox)
```json
{"id":"F-101","technique":"SQLi","family":"injection","severity":"high",
 "status":"confirmed","source":"manual",
 "file":"app/db.py","line":42,"cwe":"CWE-89",
 "dataflow":["routes/item.py:11 request.args['id']","app/db.py:42 cursor.execute(\"...\"+id)"],
 "code_excerpt":"cursor.execute(\"SELECT * FROM items WHERE id=\"+id)","confidence":"high",
 "summary":"user id concatenated into SQL","evidence":["evidence/F-101/trace.md"],
 "impact":"","remediation":"","target_link":"","ts":"..."}
```
`source` ∈ `manual` | `sast:<tool>` | `sca:<tool>` | `secret:<tool>` | `iac:<tool>`.
`status` uses the existing enum (suspected | confirmed | exploited | exploitable-not-detonated | not-exploitable | not-tested).
**Always create and update findings via `bash lib/record_finding.sh '<json>'`**. It validates the v1 schema, uses stable IDs and mode-specific fingerprints, merges evidence/reproduction arrays, and atomically promotes status under a lock. Never append or rewrite `findings.jsonl` directly. This applies to Phase-4 variant analysis and live confirmation updates.

## Phase 4 — Confirm (variant analysis + grey-box)
1. **Variant analysis** — for each `confirmed` finding, sweep the tree for siblings of the same sink pattern (`rg` the exact sink). Record each as its own finding (dedup). This is the highest-ROI step in an audit.
2. **Grey-box bridge** — if the engagement also has in-scope `targets`: for each `confirmed` finding that maps to an HTTP entry point (from the codemap), dispatch the **`exploit-agent`** with the finding id to confirm it against the live app (RoE-gated: destructive only if `destructive_allowed`). Set `target_link` and update `status` (`exploited` / `exploitable-not-detonated`). Scope-check every live request.
3. **Prove the runtime, not the source.** Grey-box confirmation observes the
   *deployed* behavior — it does not infer it (see the two-lens filter in
   `playbooks/code/_catalog.md`):
   - **Container user:** `docker exec` gives a **root shell regardless** of what
     the app runs as. Read `/proc/1/status` `Uid:` (real/effective/saved) of the
     actual app process. `Uid: 0 2000 0 2000` = effective-dropped but **saved-uid
     0 → root recoverable** (incomplete privilege drop, CWE-271) — neither "runs
     as root" nor a full drop.
   - **Async sinks:** don't claim "auto-fires" until a worker is proven to consume
     the job. If none runs locally, invoke the **identical** production sink
     synchronously (`rails runner`) to prove the sink executes on attacker input,
     and prove the worker exists in the shipped topology separately — say which
     half you proved which way.
   - **Severity is re-derived, not inherited:** a scanner "runs as root / HIGH" or
     a CVE row can be wrong in **both** directions. Set severity from proven
     real-world impact + minimal rights required.

## Phase 5 — Report
Finalise `state/notes.md` (it feeds the report's Background & Environment section). Set `loop.json.phase: report`, dispatch the **`reporter`** (uses `web-reporting`, which renders the code-finding fields: file:line, data-flow, excerpt, CWE). Surface the `report.md` path + a short summary (counts by severity, confirmed vs suspected, notable chains, scanner-coverage gaps) to the operator.

## Harness tooling gotchas
- **`record_finding.sh` upserts by stable ID:** re-run
  `PENTEST_ENGAGEMENT_DIR=<dir> bash "$HARNESS/lib/record_finding.sh" '<json>'`
  with the **same id** to update severity/status/evidence (e.g. after grey-box:
  `status: exploited`). Never edit `findings.jsonl` directly.
- **The default interactive shell may not be bash** (e.g. `nu`): the `Bash` tool
  runs `bash`, but a raw shell can be `nu`, where `FOO=bar cmd` and `$(...)` don't
  parse. Prefer the `Bash` tool; in `nu` use `with-env {FOO: bar} { ... }`.
- **A vendored `rg` can mangle matches** (replaces the matched term in the output
  with a stray character). If ripgrep output looks corrupted, fall back to
  `grep -rn`.
- **`scope-guard` blocks off-host literals** in commands (e.g. a docker gateway
  IP) even for a legitimate internal-SSRF PoC — put the target *value* in a file
  and pass the file, keeping the command's literal network arg the in-scope host.

## Resumability & stop conditions
- `loop.json` tracks `phase` + `families_done`/`families_pending`; a re-run continues, never restarts from zero.
- Stop and ask the operator on: missing/ambiguous `source_path` or authorization, a grey-box step that needs `destructive_allowed: true` for a high-impact path, or core tools (`rg`/`jq`) missing.
