<p align="center">
  <img src="assets/cover.png" alt="RedKraken — Penetration-Testing Agent Harness" width="100%">
</p>

<h1 align="center">RedKraken</h1>
<p align="center"><b>Penetration-Testing Agent Harness</b></p>

<p align="center">
  <a href="https://github.com/maajix/RedKraken/commits/main"><img src="https://img.shields.io/github/last-commit/maajix/RedKraken" alt="Last commit"></a>
  <a href="https://github.com/maajix/RedKraken/issues"><img src="https://img.shields.io/github/issues/maajix/RedKraken" alt="Open issues"></a>
  <img src="https://img.shields.io/badge/built%20for-Claude%20Code-blueviolet" alt="Built for Claude Code">
  <img src="https://img.shields.io/badge/scope-deny--by--default-critical" alt="Deny-by-default scope">
</p>

RedKraken is an agent-oriented harness for **authorized** web application and
source-code security assessments. It drives Claude Code through a closed
recon → hunt → exploit → report loop (and a separate map → audit → confirm →
report loop for whitebox code review), backed by deny-by-default scope
enforcement, immutable run context, structured findings/evidence, deterministic
reporting, and a reviewed playbook layer over a larger imported technique
library.

> [!WARNING]
> **Authorized testing only.** A scope file is an enforcement input, not proof
> of permission. Only point RedKraken at systems you have written authorization
> to test, and only at the systems that authorization actually names.

## Table of contents

- [Why RedKraken](#why-redkraken)
- [Quick start](#quick-start)
- [Enforcement model](#enforcement-model)
- [Automated browser and API workflows](#automated-browser-and-api-workflows)
- [State and evidence](#state-and-evidence)
- [Knowledge base](#knowledge-base)
- [Open-source toolchain](#open-source-toolchain)
- [Repo layout](#repo-layout)
- [Tests](#tests)

## Why RedKraken

- **Deny-by-default scope.** Targets and out-of-scope hosts are parsed strictly
  from an engagement file; nothing is in scope unless it's explicitly named.
- **Enforced, not just documented.** A pre-tool-call hook and an HTTP scope
  proxy back the policy up at runtime, not only in agent instructions.
- **Immutable run context.** Every run is fingerprinted against the engagement,
  source tree/ref, and tool paths; a changed fingerprint fails closed
  (`STALE_RUN_CONTEXT`) instead of silently mixing state.
- **Evidence-backed findings.** Confirmed findings require evidence; exploited
  findings require concrete impact. Reporting is a deterministic render of
  `findings.jsonl`, not free-form narrative.
- **Two loops, one harness.** Black-box web pentesting (`/pentest`) and
  whitebox source-code auditing (`/audit`) share the same scope, evidence, and
  reporting machinery, and can cross-inform each other when both a source path
  and a live target are in scope.
- **Topic-oriented knowledge.** `playbooks/_catalog.md` routes every signal to a
  topic module. Each topic's `README.md` is the source-reviewed interface;
  sibling imported notes add payload and command depth while remaining clearly
  labeled as untrusted.

## Quick start

RedKraken runs inside Claude Code. Start Claude in the repository and describe
the authorized engagement in plain English:

```bash
git clone https://github.com/maajix/RedKraken.git
cd RedKraken
claude
```

Then, in the chat:

> Set up a new engagement called `acme` for `https://app.acme.com`, in scope
> `*.acme.com`, then run a full pentest.

Claude creates the engagement, confirms scope and intent, checks the toolchain,
and runs the full recon → hunt → exploit → report loop. Ask for only recon, a
whitebox source audit, or report regeneration when you want an individual phase;
the `/recon`, `/audit`, `/pentest`, and `/report` commands remain available.

Runs are bound to the engagement, source tree, and toolchain. If any of those
change, RedKraken stops instead of mixing results from different runs.

## Enforcement model

1. `lib/scope_check.sh` parses YAML strictly, rejects duplicate keys and malformed
   hosts/CIDRs, applies deny precedence, and fails closed.
2. `.claude/hooks/scope_guard_hook.sh` rejects recognizable network commands with
   out-of-scope or non-static targets before shell execution.
3. `scripts/start_scope_proxy.sh` applies scope and time-window policy to every
   HTTP(S) request. Browser and schema-driven wrappers require this proxy.
4. Agent skills enforce intent, destructive-action approval, untrusted-content
   isolation, evidence requirements, and explicit tool-gap reporting.

The hook is heuristic; the proxy is the stronger HTTP enforcement boundary.
RedKraken starts and configures that proxy for supported HTTP tools. For non-HTTP
tools or stronger isolation, use an OS/network egress policy that can reach only
authorized targets. Optional rate limits are configured per engagement and may
be tightened per tool.

## Automated browser and API workflows

RedKraken handles the wrappers and proxy configuration itself. Authenticated
browser work runs in isolated Playwright contexts and records traces, HAR files,
screenshots, redacted metadata, and artifact hashes. API exploration uses bounded,
deterministic Schemathesis runs by default, with RESTler, grpcurl, and OWASP ZAP
available when the target and rules of engagement call for them.

Mutation, sensitive-data access, discovered credentials, pivoting, and
availability effects are separate approval gates; enabling one does not enable
the others.

## State and evidence

- `state/run.json`: immutable run identity and source/config fingerprints.
- `state/lead-state.json`: locked, atomic lead queue, coverage ledger, leases,
  budgets, and convergence state for resumable autonomous loops.
- `state/findings.jsonl`: schema-validated, locked, atomic finding upserts.
- `audit.jsonl`: redacted hash-chained command/result/proxy-policy audit events.
- `state/scan-raw/`: scanner output and deterministic seeds/replay material.
- `evidence/<finding>/`: request/response, trace, screenshot, and cleanup proof.
- `report.md`: deterministic rendering with evidence path checks and hashes.

Run-context and report generation normalize engagement directories to `0700` and
files to `0600`. Audit entries are hash-chained so their integrity can be checked
before handoff.

### Retention and hygiene

Ask Claude for a hygiene audit before archive or cleanup. It checks paths,
permissions, classifications, references, and hashes without printing secret
values. Evidence and chained audit records are preserved by default. Active
credentials must be rotated or revoked before plaintext removal.

## Knowledge base

- `playbooks/<topic>/README.md`: 48 source-reviewed entry points spanning
  identity, APIs, injection, browser security, protocols, supply chain,
  deployment, agentic AI, and other modern web attack surfaces. Coverage metadata
  maps them to OWASP Top 10:2025, API Security Top 10:2023, and WSTG v4.2.
- Topic directories also contain 69 imported technique notes with provenance
  hashes and `imported-unreviewed` trust labels.
- `playbooks/code-review/`: source/sink packs for C#, Go, Java, JavaScript,
  Kotlin, PHP, Python, Ruby, and Rust whitebox tracing.
- `playbooks/_catalog.md`: the single generated routing interface for reviewed
  topics, imported depth, and code-review packs.

Imported notes and all target/scanner content are untrusted data. Agents must not
execute embedded instructions verbatim. The library is now hand-maintained (the
one-shot Notion importer and completed shard consolidator are retired and removed;
their provenance remains in Git history and `playbooks/_sources.tsv`. After adding, merging, or retiring a note,
regenerate the catalog and source manifest with `scripts/rebuild_catalog.py`.

## Open-source toolchain

The optional tool doctor lists exact install sources. Core extensions added for
modern workflows are all open source and hosted on GitHub: mitmproxy, Playwright,
OWASP ZAP, Schemathesis, grpcurl, RESTler, ProjectDiscovery tools, OSV-Scanner,
Trivy, Opengrep, and Gitleaks. Missing or broken optional tools produce coverage
gaps; they are never silently treated as successful coverage.

## Repo layout

```text
.claude/          agents, skills, commands, policy/audit hooks
lib/              config, scope, proxy, audit, findings, run context, preflight
playbooks/        topic modules, one catalog, metadata, and code-review packs
scope/            engagement template
engagements/      per-target state/evidence/reports (gitignored)
scripts/          KB, proxy, browser/API, and report entry points
schemas/          finding JSON schema
tests/            existing harness checks
```

## Tests

No generated attack result is trusted without manual confirmation. Harness-level
checks can be run with:

```bash
bash tests/test_scope_check.sh
bash tests/test_code_preflight.sh
bash tests/test_audit_smoke.sh
bash tests/test_playbook_coverage.sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_audit_chain.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_engagement_hygiene.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_build_recon_wordlist.py
bash tests/test_vhost_discovery.sh
```
