---
id: modern-exceptional-condition-security
title: Fail-Open and Partial-Failure Security
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Fail-Open and Partial-Failure Security

## Model first

Add failure edges to the workflow graph. A rejected or `500` response does not
prove that authorization, quota, balance, transaction, event, or rollback policy
held in the authoritative state.

## Safe detection

1. For a synthetic workflow, record preconditions, atomicity expectations,
   rollback behavior, emitted events, retry policy, and final-state invariants.
2. Vary missing/extra parameters, invalid type/enum combinations, boundary values,
   unsupported content types, duplicate fields, and cancellation one at a time.
3. In an isolated test environment with explicit fault-injection permission,
   introduce one dependency timeout, disconnect, queue failure, callback failure,
   or consumer error at a known transition. Do not create production resource
   pressure or broad outages.
4. Compare response, audit log, database/object state, quota/balance, emitted
   event, notification, and retry. Repeat only to establish determinism.
5. Stop at the first tester-owned unauthorized access, skipped control, duplicate
   value, or privileged partial state.

## Confirmation and evidence

Save the injected fault or malformed input, transition point, response, logs,
before/after state, emitted messages, retry outcome, invariant violated, and
cleanup. Verbose errors without a security impact remain observations.

## Remediation

Fail closed at trust boundaries; use atomic transactions/outboxes and compensating
actions; distinguish retryable from terminal errors; make consumers idempotent;
enforce invariants with database constraints; bound retries/resources; and test
rollback and cancellation paths as first-class behavior.

## Sources

- [OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- [OWASP WSTG: Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/)

