---
id: modern-transaction-integrity-payment-workflows
title: Transaction and payment workflow integrity
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: high
---

# Transaction and payment workflow integrity

## Threat model

Checkout, authorization, capture, refund, payout, credit, discount, inventory, and
ledger workflows fail when the server trusts client totals, accepts replayed or
out-of-order events, loses actor/tenant binding, or records inconsistent financial
state across retries and partial failures.

## Safe detection

1. Use a sandbox or explicitly authorized test merchant, synthetic instruments, and
   reversible amounts. Map quote -> order -> authorization -> capture -> settlement
   -> refund/void plus failure, retry, cancellation, and dispute states.
2. Record the authoritative server-side amount, currency, merchant, payer, payee,
   inventory, discount, tax, and ledger entry at each transition.
3. Replay one tester-owned operation with the same idempotency key; then vary exactly
   one bound field or send one out-of-order transition. Never change a real payment.
4. Test duplicate callbacks, delayed delivery, concurrent requests, partial provider
   failure, and stale client state with bounded synthetic transactions.
5. Verify that UI status, provider status, order state, inventory, and double-entry
   ledger converge. Stop before real funds, irreversible settlement, or third-party
   accounts are affected.

## Confirmation and evidence

Save redacted request/event identifiers, before/after authoritative states, provider
sandbox result, idempotency behavior, ledger entries, and cleanup/void evidence.
Confirm only an unauthorized value/state transition, duplicate economic effect, or
provable ledger/provider inconsistency.

## Remediation

Compute financial values server-side; bind every transition to actor, tenant,
merchant, amount, currency, order, and purpose; enforce a transition state machine;
use idempotency and replay protection; verify signed provider events; reconcile the
provider, order, inventory, and ledger; alert on impossible transitions.

## Sources

- [OWASP WSTG v4.2 Testing for Business Logic](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README)
- [PCI DSS v4.0.1 document library](https://www.pcisecuritystandards.org/document_library/)
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)
