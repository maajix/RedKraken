---
name: api-stateful
description: Schema-driven and stateful security testing for OpenAPI, GraphQL, gRPC, and asynchronous APIs using OSS tools, producer-consumer workflows, role differentials, and replayable minimized failures.
---

# Stateful API Testing

Prefer a local OpenAPI/GraphQL schema or captured traffic over blind endpoint
guessing. Import schemas into OWASP ZAP and use Schemathesis for property-based
generation. Use RESTler only for deeper producer-consumer exploration, and grpcurl
for gRPC reflection and invocation. Missing tools become explicit coverage gaps.

## Workflow

1. Validate and hash the schema; override every declared server with the in-scope
   target so a hostile schema cannot redirect testing.
2. Derive producer/consumer relationships and persist workflows such as
   create -> read -> update -> delete. Save and minimize every failure seed.
3. Replay operations and sequences across anonymous, peer, owner, and privileged
   identities. Diff both response and resulting state.
   Inventory selectors from paths, parameters, bodies, headers, cookies, links,
   exports, filenames, schema IDs, client bundles, and unused client APIs. Record
   representation and any deterministic client/source transform; test the same
   synthetic object across owner and peer rather than enumerating real objects.
4. Test undocumented fields, duplicate parameters, content-type variants, batch
   requests, pagination, idempotency keys, callbacks, GraphQL aliases/fragments/
   persisted queries/subscriptions, and gRPC streaming metadata.
5. Cap generated examples and sequence length. Apply request-rate constraints
   only when the operator explicitly set `rate_limit_enabled: true`.

For bounded Schemathesis execution, the orchestrator ensures the shared proxy is
healthy and the agent uses the harness wrappers. A sub-agent halts and reports an
unhealthy proxy; it never starts one. Mutation additionally requires
`mutation_allowed: true`.
Real sensitive records, discovered credentials, cross-service pivots, and
availability effects independently require `sensitive_data_access_allowed`,
`credential_use_allowed`, `pivoting_allowed`, and
`availability_impact_allowed` respectively:
```bash
python3 lib/proxy_supervisor.py health "$PENTEST_ENGAGEMENT_DIR"
./scripts/run_scoped_http.sh bash scripts/run_schemathesis.sh \
  "$PENTEST_ENGAGEMENT_DIR" "<schema>" "<in-scope-base-url>"
```
The wrapper fixes seed, example cap, redirects, output location, and read-only
methods by default. Do not replace it with schema-provided server URLs.

Write normalized endpoints/workflows to state, raw output to `state/scan-raw/`,
and only validated findings through `record_finding.sh`.

## Raw-output contract

- Preserve full scanner output under `state/scan-raw/` with directory `0700` and
  files `0600`; cap stdout or write directly there before reading it.
- Return only structured counts, hashes, redacted high-signal slices, and evidence
  paths. Never inline raw credentials, cookies, tokens, personal data, or full
  client responses into model/orchestration context.
- Truncation must never destroy the only evidence copy. Parse/truncation/tool
  failures are `not-tested` coverage, never successful coverage.
