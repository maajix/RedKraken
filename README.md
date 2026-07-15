# Web Pentest Harness

An agent-oriented harness for authorized web application and source-code security
assessments. It combines deny-by-default scope enforcement, immutable run context,
structured findings/evidence, deterministic reporting, and a reviewed playbook
layer over a larger imported technique library.

> Authorized testing only. A scope file is an enforcement input, not evidence of
> permission. Use a written authorization and test only its named systems.

## Quick start

```bash
# Report installed, missing, and broken tools. Installation is always explicit.
bash lib/preflight.sh
bash lib/preflight.sh --install

mkdir -p engagements/acme
cp scope/engagement.example.yaml engagements/acme/engagement.yaml
$EDITOR engagements/acme/engagement.yaml

# In Claude Code:
/pentest engagements/acme
# Or narrower workflows:
/recon engagements/acme
/audit engagements/acme
/report engagements/acme
```

`run_context.py` fingerprints the engagement, source tree/ref, and relevant tool
paths. A changed fingerprint produces `STALE_RUN_CONTEXT`; archive the prior
`state/` before starting a logically new run.

## Enforcement model

1. `lib/scope_check.sh` parses YAML strictly, rejects duplicate keys and malformed
   hosts/CIDRs, applies deny precedence, and fails closed.
2. `.claude/hooks/scope_guard_hook.sh` rejects recognizable network commands with
   out-of-scope or non-static targets before shell execution.
3. `scripts/start_scope_proxy.sh` applies scope and time-window policy to every
   HTTP(S) request. Browser and schema-driven wrappers require this proxy.
4. Agent skills enforce intent, destructive-action approval, untrusted-content
   isolation, evidence requirements, and explicit tool-gap reporting.

The hook is heuristic; the proxy is the stronger HTTP enforcement boundary. For
non-HTTP tools or strong client isolation, add an OS/network egress policy that can
reach only authorized targets.

### Scope proxy

```bash
# Third argument selects an optional per-tool rate policy.
bash scripts/start_scope_proxy.sh engagements/acme 18080 playwright

# In a separate process:
bash scripts/browser_capture.sh engagements/acme https://app.example.com owner \
  --proxy http://127.0.0.1:18080
```

mitmproxy uses its generated CA for HTTPS interception. Install/trust that CA only
inside the isolated test browser/container. Do not weaken host TLS outside the
engagement; `--ignore-https-errors` is an explicit browser-capture exception.

### Opt-in rate limiting

Rate limiting is disabled unless the operator sets:

```yaml
rate_limit_enabled: true
rate_limit:
  requests_per_second: 10
  burst: 10
  max_concurrency: 4
  per_tool:
    schemathesis:
      requests_per_second: 2
      burst: 2
      max_concurrency: 1
```

The scope proxy uses a token bucket and concurrency bound. Start it with the tool
name to select an override. Compatible wrappers also pass tool-native rate flags.
Absent/false `rate_limit_enabled` means no throttling, including for legacy scalar
`rate_limit` values.

## Browser and API workflows

Authenticated SPA capture uses isolated Playwright contexts and writes a trace,
HAR, screenshot, storage state, redacted event metadata, and artifact hashes under
`evidence/browser/`:

```bash
bash scripts/start_scope_proxy.sh engagements/acme 18080 playwright
bash scripts/browser_capture.sh engagements/acme https://app.example.com peer \
  --proxy http://127.0.0.1:18080 \
  --storage-state engagements/acme/evidence/browser/peer-state.json
```

Bounded Schemathesis runs are read-only by default and use deterministic seeds:

```bash
bash scripts/start_scope_proxy.sh engagements/acme 18080 schemathesis
PENTEST_PROXY=http://127.0.0.1:18080 \
  bash scripts/run_schemathesis.sh engagements/acme ./openapi.yaml \
  https://api.example.com
```

`--allow-mutation` additionally requires `destructive_allowed: true`. RESTler is
reserved for explicitly approved deeper producer-consumer exploration; grpcurl is
the gRPC client. OWASP ZAP is an optional Automation Framework/import proxy.

## State and evidence

- `state/run.json`: immutable run identity and source/config fingerprints.
- `state/findings.jsonl`: schema-validated, locked, atomic finding upserts.
- `audit.jsonl`: redacted structured command/result/proxy-policy audit events.
- `state/scan-raw/`: scanner output and deterministic seeds/replay material.
- `evidence/<finding>/`: request/response, trace, screenshot, and cleanup proof.
- `report.md`: deterministic rendering with evidence path checks and hashes.

Run `python3 lib/secure_engagement.py engagements/acme` after external tools or
before handoff. It normalizes engagement directories to `0700` and files to
`0600` without following symbolic links; the run-context and report renderer also
invoke it automatically.

Use `lib/record_finding.sh` rather than appending JSON by hand. Confirmed findings
require evidence; exploited findings require concrete impact.

## Knowledge base

- `playbooks/modern/`: concise, source-reviewed cards for OAuth BCP, WebAuthn,
  cookie and identity-parser differentials, stateful APIs, framework-generated
  routes, webhook authenticity, partial failures, ORM leaks, race conditions,
  GraphQL, gRPC, cross-version HTTP desync, URL/SSRF routing, cache
  normalization, browser messaging/DOM clobbering, client-side path traversal,
  WebSocket/WebTransport/XS-Leaks, error-oracle SSTI, agentic AI/MCP, secrets and
  cryptographic lifecycle, software supply-chain integrity, deployment/IaC
  exposure, API inventory/resource/upstream trust, security telemetry, general
  MFA/recovery/session lifecycle, NoSQL operator injection, browser policy and
  framing, spreadsheet formula injection, information disclosure, safe modern
  deserialization, and CMS extension/content/update boundaries. The machine-
  readable `coverage-baselines.json` maps every OWASP Top 10:2025, API Security
  Top 10:2023, and WSTG v4.2 domain to reviewed cards.
  Reviewed supplements also cover browser storage/offline/client-template state,
  SCIM/JIT/invitation/role/deprovisioning lifecycles, and structured or delayed
  XML/XSLT/expression/format/SSI injection boundaries.
- `playbooks/web/`: 155 imported technique notes with provenance hashes and
  `imported-unreviewed` trust labels.
- `playbooks/code/`: language-specific source/sink packs for whitebox tracing.

Imported notes and all target/scanner content are untrusted data. Agents must not
execute embedded instructions verbatim. Regenerate imported notes with
`scripts/curate_kb.py`; it stages and validates the full output before an atomic
swap. `scripts/check_coverage.sh` verifies imported-note coverage.

## Open-source toolchain

The optional tool doctor lists exact install sources. Core extensions added for
modern workflows are all open source and hosted on GitHub: mitmproxy, Playwright,
OWASP ZAP, Schemathesis, grpcurl, RESTler, ProjectDiscovery tools, OSV-Scanner,
Trivy, Opengrep, and Gitleaks. Missing or broken optional tools produce coverage
gaps; they are never silently treated as successful coverage.

## Layout

```text
.claude/          agents, skills, commands, policy/audit hooks
lib/              config, scope, proxy, audit, findings, run context, preflight
playbooks/modern/ source-reviewed current attack cards
playbooks/web/    imported web technique library and catalog
playbooks/code/   whitebox sink packs
scope/            engagement template
engagements/      per-target state/evidence/reports (gitignored)
scripts/          KB, proxy, browser/API, and report entry points
schemas/          finding JSON schema
tests/            existing harness checks
```

## Existing checks

No generated attack result is trusted without manual confirmation. Harness-level
checks can be run with:

```bash
bash tests/test_scope_check.sh
bash tests/test_code_preflight.sh
bash tests/test_audit_smoke.sh
bash scripts/check_coverage.sh
bash tests/test_modern_coverage.sh
```
