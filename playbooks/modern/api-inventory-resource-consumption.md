---
id: modern-api-inventory-resource-consumption
title: API Inventory, Resource Bounds, and Upstream Consumption
family: config-iac
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# API Inventory, Resource Bounds, and Upstream Consumption

## Threat model

Map every host, version, route, schema, async worker, batch/export/import path,
GraphQL/gRPC surface, and third-party API. For each operation record authorization,
object/state effects, maximum input/output/work/cost, timeout/cancellation, and
which upstream data is trusted.

## Safe detection

1. Reconcile gateway/routes, generated schemas, client bundles, traffic, DNS,
   deployment manifests, and documentation. Compare current, beta, deprecated,
   shadow, alternate-host, debug, and management variants for consistent controls.
2. Test one dimension at a time with tester-owned data: page size, batch count,
   upload/decompression size, query depth/complexity, field expansion, export
   range, async job count, and expensive verification or provider calls.
3. Start below the documented limit and cross it by the smallest increment. Stop
   after proving a missing per-request ceiling or charge/quota invariant. Never
   infer denial of service from a slow response and never flood by default.
4. For upstream APIs, substitute a harness-owned provider and vary redirect,
   timeout, status, content type, schema, length, and benign untrusted fields.
   Check TLS/host validation, egress allowlists, parsing, sanitization, retries,
   caching, and whether upstream data reaches injection or authorization sinks.
5. Re-run alternate versions and channels as anonymous, peer, owner, and
   privileged test identities; record authoritative after-state and provider hits.

## Confirmation and evidence

Confirm an undocumented/deprecated surface with weaker controls, a single bounded
request that violates an explicit resource/cost invariant, or a harness-owned
upstream response that crosses a trust boundary. Load, concurrency, recursive
expansion, decompression-bomb, billing-impact, and real-provider testing require
explicit authorization. Save inventory diff, minimized seed, resource/cost
measurement, upstream transcript, control request, and cleanup.

## Remediation

Maintain an owner/version/environment API inventory; retire old hosts and versions;
apply gateway and service controls consistently; bound every request dimension and
aggregate spend; limit pagination/batches/query complexity; enforce timeouts and
cancellation; validate and sanitize provider data; restrict egress/redirects; and
use circuit breakers with safe retry/idempotency behavior.

## Sources

- [OWASP API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP API8:2023 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [OWASP API10:2023 Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

