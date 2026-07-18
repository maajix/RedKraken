---
id: modern-api-stateful-business-logic
title: Stateful API Authorization and Business Flows
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-10
destructive_risk: medium
---

# Stateful API Authorization and Business Flows

## Model first

Build a workflow graph and an identity/object/action/state matrix. Map which
operation creates each identifier and which later operations consume it. Include
jobs, callbacks, batch endpoints, exports, idempotency keys, pagination cursors,
and asynchronous completion rather than testing endpoints independently.

## Safe detection

1. Capture legitimate owner workflows using operator-created fixtures.
2. Inventory object selectors from paths, query/body fields, headers, cookies,
   links, exports, static filenames, GraphQL/gRPC IDs, client bundles, and unused
   client APIs. Record representation type and any deterministic transformation
   shipped in client/source logic; encoding or hashing is not authorization.
3. Replay one step as anonymous, peer, cross-tenant, owner, and privileged roles;
   change only object, property, action, or workflow state.
4. Try duplicate, reordered, skipped, and repeated transitions; stale tokens;
   read-after-delete; cancel-after-complete; and idempotency-key reuse.
5. Compare list/detail/download/update/delete and alternate method/content-type
   representations one dimension at a time. Never mass-enumerate or download
   real-user objects.
6. For writable objects, add or change one unauthorized property at a time.
7. Compare response and authoritative after-state. A denial response with a
   completed side effect is a confirmed authorization failure.
8. Use Schemathesis for bounded schema generation and RESTler for deeper
   producer-consumer sequences. Keep generated mutation behind the RoE gate.

## Confirmation and evidence

Record role labels, state before, exact operation sequence, state after, cleanup,
and the minimized deterministic seed. Automation output is a lead until a stable
unauthorized read or change is reproduced.

## Remediation

Enforce object, property, function, tenant, and state-transition authorization in
the service; bind idempotency and workflow tokens to actor and operation; protect
sensitive business flows with business-aware controls, not IP throttling alone.

## Sources

- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP API6:2023 Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [Microsoft RESTler](https://github.com/microsoft/restler-fuzzer)
