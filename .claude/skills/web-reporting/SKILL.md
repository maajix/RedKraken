---
name: web-reporting
description: Turn the structured findings of a web engagement into a professional penetration-test report. Use during the reporting phase, or when asked to (re)generate the report from findings.jsonl.
---

# Web Reporting

Build `engagements/<n>/report.md` with `python3 scripts/render_report.py <engagement>` from `state/findings.jsonl` — the data is the source of truth, not memory. Every claim must trace to a finding with evidence on disk. This covers both blackbox (`/pentest`) and whitebox (`/audit`) findings — they share one `findings.jsonl`.

## Process

1. Verify `state/run.json` through `lib/run_context.py`, then read `engagement.yaml` and `state/findings.jsonl`.
2. Group findings; drop `not-tested`/`not-exploitable` from the main body but list them in a coverage appendix (honesty about what was and wasn't reachable).
3. Order by severity (Critical → High → Medium → Low → Info).
4. Run the deterministic renderer, which hashes evidence, rejects path escapes, and marks missing artifacts as pending. Agent review may identify wording gaps but does not replace the generated facts.

## Severity

Qualitative, impact × exploitability. Use CVSS-ish reasoning but state it plainly:
- **Critical** — unauthenticated RCE, full DB compromise, auth bypass to admin.
- **High** — authenticated RCE, SQLi with data access, account takeover, SSRF to internal/cloud-metadata.
- **Medium** — stored XSS, IDOR on sensitive data, meaningful info disclosure.
- **Low** — reflected XSS needing interaction, verbose errors, missing headers with real impact.
- **Info** — hygiene/observations.

## Report structure (`report.md`)

```
# Web Application Penetration Test — <name>
## Executive summary            (plain-language risk, headline findings, counts by severity)
## Scope & rules of engagement  (targets, out-of-scope, intent, dates, destructive_allowed)
## Background & Environment      (optional; rendered from `state/notes.md` when present: stack/versions, auth & tenancy model, observed defenses, obtained-credential locations — non-vuln environment facts)
## Methodology                  (recon → triage → hunt → exploit; tools used)
## Findings
### [SEVERITY] <title>           (one block per finding; `title` falls back to `technique`/`id`)

**TL;DR:** <one-line `summary`>

---

#### Summary                   (fuller `description`, falls back to `summary`: what it is, why it exists)
#### Details                   (ID / Affected / Status / Source / CWE bullets, then — WHITEBOX only —
                                 the `dataflow` steps as an ordered list (source → … → sink) and the
                                 `code_excerpt` in a fenced, language-tagged block)
#### PoC                        (finding.repro steps in a fenced block; for whitebox, the trace in evidence/<id>/trace.md)
#### Evidence                   links to evidence/<id>/...
#### Impact                     concrete business impact
#### Recommended Fix            specific, actionable fix (+ reference to the playbook's prevention notes)
## Coverage & limitations       (techniques not tested + why: tool unavailable, out of scope, auth required; whitebox: scanner-coverage gaps per family)
## Appendix: command audit      (summarise engagements/<n>/audit.jsonl)
```

**Rendering rule:** whitebox findings carry `file`/`line`/`dataflow`/`cwe`/`code_excerpt`/`source`; render the dataflow/code-excerpt part of "Details" for them. Blackbox findings lack those fields — omit that part, render as before (nothing breaks). If a whitebox finding also has a `target_link` + live confirmation (grey-box), report both the code root cause and the live proof.

Findings should carry `title` (crisp, specific heading) and `description` (fuller root-cause narrative) alongside the existing `summary` (TL;DR) — see `web-vuln-hunter`/`code-auditor` agent instructions.

Pull remediation language from the relevant `playbooks/web/<technique>.md` or `playbooks/code/sinks-<lang>.md` so fixes are consistent with the knowledge base. Keep it client-readable: lead with impact, keep payloads/code in reproduction/evidence sections.
