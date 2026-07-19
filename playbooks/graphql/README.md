---
id: modern-graphql-authorization-cost
title: GraphQL Authorization, Batching, and Cost
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# GraphQL Authorization, Batching, and Cost

## Safe detection

1. Inventory operations from shipped documents, traffic, introspection when
   enabled, persisted-query manifests, and subscription handshakes.
2. Apply the identity/object/action matrix at every node and edge. Test global
   IDs, nested resolvers, aliases, fragments, interfaces/unions, and node lookup.
3. Request one normally hidden field at a time and submit one unauthorized input
   property at a time. A schema omission is not an authorization control.
4. Compare single operations with JSON batching, aliases, and persisted queries;
   verify limits and authorization cannot be bypassed through alternate shapes.
5. Exercise subscriptions for handshake auth, per-event authorization, tenant
   isolation, token expiry, and logout. Stop before load testing.
6. Measure whether depth, breadth, aliases, list cardinality, and resolver cost
   are bounded using very small increments. Do not attempt resource exhaustion.
7. Test GraphQL-over-HTTP behavior with a minimal `__typename` query: supported
   methods, JSON and GraphQL media types, `Accept`, operation selection, variables,
   parse/validation/execution status handling, and partial errors. Require a
   disposable mutation sent by `GET` to be rejected without changing state.
8. Compare transport variants, batching and persisted-query fallbacks so edge and
   application authorization, CSRF, caching, and content-type controls agree.
   Treat GraphQL-over-HTTP as a Stage 2 draft and record the tested draft version.

## Confirmation and evidence

Confirm unauthorized fields, objects, mutations, or subscription events with a
minimal query and role differential. Record operation name/hash, variables,
identity, normalized response, and after-state. Report missing cost controls as a
finding only when bounded tests show material amplification or policy failure.

## Remediation

Authorize in resolvers and the domain layer for nodes and edges, allowlist
production operations when practical, cap depth/breadth/aliases/batches and list
sizes, use cost analysis, and revalidate long-lived subscription sessions.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [GraphQL](api-graphql.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL September 2025 Specification](https://spec.graphql.org/September2025/)
- [GraphQL over HTTP Stage 2 Draft](https://graphql.github.io/graphql-over-http/draft/)
