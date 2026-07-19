---
id: modern-webhook-event-authenticity
title: Webhook Authenticity, Replay, and Idempotency
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Webhook Authenticity, Replay, and Idempotency

## Safe detection

1. Use a provider sandbox or harness-owned signer. Capture a valid test delivery's
   raw bytes, signature headers, delivery/event ID, timestamp, event type, and
   resulting tester-object state.
2. Change one invariant at a time: one body byte, signature, endpoint/test-vs-live
   secret, timestamp age, delivery ID, event type/action, content type, duplicate
   JSON member, or body encoding. Verify signatures over the provider-defined raw
   representation before parsing or business processing.
3. Replay the valid delivery and simulate a legitimate retry. Verify duplicates
   are rejected or absorbed idempotently without suppressing valid retries.
4. Check that the authenticated event type, account/tenant, object, and action are
   authorized again at the consumer and at every asynchronous queue boundary.
5. Use tester-owned orders/accounts/repositories only. Do not generate live
   payments, entitlements, deployments, or production repository mutations.

## Confirmation and evidence

Save raw delivery bytes, redacted signature inputs, provider mode, secret identity,
timestamps, delivery/event IDs, queue attempts, before/after state, retry result,
and cleanup. A `2xx` alone is not proof that a forged event was processed.

## Remediation

Verify with the provider's library over the unmodified raw body; select secrets by
endpoint/provider/tenant; enforce timestamp freshness; prevent delivery/event
replay; make consumers transactionally idempotent; validate event type and object
authorization; and preserve signature context across asynchronous processing.

## Sources

- [Stripe webhooks](https://docs.stripe.com/webhooks)
- [Stripe signature verification](https://docs.stripe.com/webhooks/signature)
- [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
