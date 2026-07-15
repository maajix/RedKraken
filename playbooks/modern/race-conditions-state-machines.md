---
id: modern-race-conditions-state-machines
title: Race Conditions and Hidden State Transitions
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Race Conditions and Hidden State Transitions

## Model first

Treat every request as a series of hidden sub-state transitions, not an atomic
operation. Prioritize single-use tokens, quota and balance checks, invitations,
verification, recovery, MFA/passkey enrollment, role changes, uploads, payments,
and multi-endpoint workflows that touch the same object.

## Safe detection

1. Build a state diagram from sequential requests using disposable fixtures.
   Record the authoritative state before and after each operation, including
   background jobs and messages.
2. Benchmark one request, then send a very small synchronized group against the
   same tester-owned fixture. Prefer HTTP/2 single-packet delivery where supported;
   use last-byte synchronization only when needed. Do not turn this into load or
   availability testing.
3. Test limit-overrun, single-endpoint, multi-endpoint, deferred, and object-
   masking patterns. Pair operations whose checks and commits may overlap, such as
   accept/revoke, verify/change, redeem/cancel, or upload/process.
4. Vary connection warming and session state so transport setup is not mistaken
   for an application race. Repeat only enough to distinguish a stable invariant
   violation from noise.
5. Minimize the request group and stop at the first reversible duplicate action,
   unauthorized state, or contradictory view. Do not race real payments, scarce
   inventory, production notifications, or other users' objects.

## Confirmation and evidence

Save the exact grouped requests, protocol and synchronization method, send/receive
timing, state snapshots, side effects, cleanup, and negative sequential control.
Timing overlap alone is suspected; the business invariant must actually fail.

## Remediation

Enforce invariants in one atomic transaction using appropriate row/version locks,
unique constraints, compare-and-swap, or idempotency records bound to actor and
operation. Recheck authorization and state at commit time and make async consumers
idempotent.

## Sources

- [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
- [The Single-Packet Attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local)
- [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)

