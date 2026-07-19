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

1. Build a bounded reference inventory from paths, query/body fields, headers,
   cookies, links, exports, static filenames, GraphQL/gRPC IDs, client bundles,
   and unused client APIs. Record integer, opaque ID, UUID, slug, filename,
   Base64, hash, composite, or client-derived representation. Reconstruct only
   deterministic transforms shipped in client/source logic; encoding or hashing
   is not authorization.
2. Capture one legitimate request and its before-state as the owner.
3. Replay the identical request as each other identity, changing only the object,
   tenant, property, or action selector under test.
4. Compare status, normalized body, timing, and authoritative after-state. A `200`
   alone is not proof; a `403` with a completed side effect is still a bug.
5. Exercise list/detail/download/update/delete, batch, export/import, nested
   object, alternate method/content-type, GraphQL node/alias,
   WebSocket/subscription, asynchronous job, and alternate-method variants.
6. Test state transitions out of order: closed/revoked/archived objects, repeated
   actions, invitation acceptance, owner removal, approval bypass, and stale-token
   reuse. Verify invariants such as "a tenant retains an owner" after every step.
7. For writable JSON, send one unauthorized property at a time to detect mass
   assignment and object-property authorization failures.

## Safety and evidence

Use reversible test data and a cleanup plan. Save redacted identity labels,
before-state, exact request, response, after-state, and cleanup result under
`evidence/<id>/`. Confirm only when an unauthorized read or change is observable.

Map coverage to OWASP API Security 2023 API1, API3, API5, and API6, plus the
corresponding WSTG authorization and business-logic controls.

For OpenAPI, GraphQL, or gRPC signals, load the matching topic `README.md` via
`playbooks/_catalog.md` and the `api-stateful` workflow. Long-lived streams and async
jobs require authorization checks after the initial request as well.

For user-controlled filters, relation traversal, `include`/`select`/`expand`, or
query-shape objects, load `playbooks/orm/README.md` and
test whether hidden related fields become boolean, count, error, or timing oracles.
For SCIM/JIT provisioning, invitations, groups/roles, tenant moves, suspension,
deletion, or identifier reuse, load `playbooks/identity-lifecycle/README.md` and
verify stale sessions/credentials and resource ownership after each transition.
For single-use actions or overlapping state changes, load
`playbooks/race-conditions/README.md`; use bounded synchronized
groups on disposable fixtures and require an actual invariant failure.

Load `playbooks/routing/README.md` for generated data/action/prefetch
routes or client-supplied internal router headers. Load
`playbooks/webhooks/README.md` for inbound signed events and retry queues. Add
failure edges with `playbooks/exceptional-conditions/README.md` when malformed input,
cancellation, or dependency/queue failure could skip controls or leave partial
privileged state.
