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
4. Test undocumented fields, duplicate parameters, content-type variants, batch
   requests, pagination, idempotency keys, callbacks, GraphQL aliases/fragments/
   persisted queries/subscriptions, and gRPC streaming metadata.
5. Cap generated examples and sequence length. Apply request-rate constraints
   only when the operator explicitly set `rate_limit_enabled: true`.

For bounded Schemathesis execution, run a tool-labelled enforcement proxy and use
the harness wrapper. Mutation additionally requires `destructive_allowed: true`:
```bash
bash scripts/start_scope_proxy.sh "$PENTEST_ENGAGEMENT_DIR" 18080 schemathesis
PENTEST_PROXY=http://127.0.0.1:18080 bash scripts/run_schemathesis.sh \
  "$PENTEST_ENGAGEMENT_DIR" "<schema>" "<in-scope-base-url>"
```
The wrapper fixes seed, example cap, redirects, output location, and read-only
methods by default. Do not replace it with schema-provided server URLs.

Write normalized endpoints/workflows to state, raw output to `state/scan-raw/`,
and only validated findings through `record_finding.sh`.
