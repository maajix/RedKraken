---
name: access-control-attacks
description: Black-box authorization and business-logic testing using identity, object, action, tenant, and workflow-state differentials. Covers BOLA/IDOR, BFLA, property authorization, mass assignment, role confusion, ownership invariants, and unsafe state transitions.
---

# Access Control & Business Logic

Build a matrix before testing: **identity x tenant x object owner x action x
workflow state**. At minimum use anonymous, non-owner peer, owner, and privileged
test identities when the engagement provides them. Never test against real-user
objects when equivalent test fixtures can prove the issue.

## Method

1. Capture one legitimate request and its before-state as the owner.
2. Replay the identical request as each other identity, changing only the object,
   tenant, property, or action selector under test.
3. Compare status, normalized body, timing, and authoritative after-state. A `200`
   alone is not proof; a `403` with a completed side effect is still a bug.
4. Exercise list/detail, batch, export/import, nested object, GraphQL node/alias,
   WebSocket/subscription, asynchronous job, and alternate-method variants.
5. Test state transitions out of order: closed/revoked/archived objects, repeated
   actions, invitation acceptance, owner removal, approval bypass, and stale-token
   reuse. Verify invariants such as "a tenant retains an owner" after every step.
6. For writable JSON, send one unauthorized property at a time to detect mass
   assignment and object-property authorization failures.

## Safety and evidence

Use reversible test data and a cleanup plan. Save redacted identity labels,
before-state, exact request, response, after-state, and cleanup result under
`evidence/<id>/`. Confirm only when an unauthorized read or change is observable.

Map coverage to OWASP API Security 2023 API1, API3, API5, and API6, plus the
corresponding WSTG authorization and business-logic controls.

For OpenAPI, GraphQL, or gRPC signals, load the matching source-reviewed card in
`playbooks/modern/` and the `api-stateful` workflow. Long-lived streams and async
jobs require authorization checks after the initial request as well.

For user-controlled filters, relation traversal, `include`/`select`/`expand`, or
query-shape objects, load `playbooks/modern/orm-relational-filter-leaks.md` and
test whether hidden related fields become boolean, count, error, or timing oracles.
For SCIM/JIT provisioning, invitations, groups/roles, tenant moves, suspension,
deletion, or identifier reuse, load `identity-provisioning-role-lifecycle.md` and
verify stale sessions/credentials and resource ownership after each transition.
For single-use actions or overlapping state changes, load
`playbooks/modern/race-conditions-state-machines.md`; use bounded synchronized
groups on disposable fixtures and require an actual invariant failure.

Load `framework-routing-trust-boundaries.md` for generated data/action/prefetch
routes or client-supplied internal router headers. Load
`webhook-event-authenticity.md` for inbound signed events and retry queues. Add
failure edges with `exceptional-condition-security.md` when malformed input,
cancellation, or dependency/queue failure could skip controls or leave partial
privileged state.
