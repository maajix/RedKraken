---
id: modern-security-logging-alerting
title: Security Logging, Alerting, and Audit Integrity
family: config-iac
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Security Logging, Alerting, and Audit Integrity

## Threat model

Trace high-value security events from application decision through structured
recording, transport, normalization, storage, correlation, alert, responder
delivery, retention, and investigation. Test confidentiality and integrity of
the telemetry itself as well as event coverage.

## Safe detection

1. Agree on a small event matrix with the operator: login success/failure, MFA or
   recovery change, authorization denial, privileged action, secret/key change,
   admin/config change, bulk export, webhook/integration change, and validation
   or dependency failure.
2. Generate one unique canary event at a time in a test tenant. Correlate request,
   actor, tenant, object, action, result, source, timestamp, event id, log record,
   alert, and responder-visible context without storing credentials or payloads.
3. Check control characters and multiline values with benign canaries; verify
   structured boundaries survive ingestion and display. Do not forge another
   user's identity or erase/overwrite production records.
4. Compare success, denial, partial failure, async completion, retry, and
   cancellation so logging reflects authoritative outcome rather than intent.
5. With an operator-provided test sink only, verify bounded transport outage,
   buffering/backpressure, duplicate handling, clock/order behavior, and whether
   a mandatory audit failure incorrectly permits a privileged action.

## Confirmation and evidence

Confirm when a required test event is absent or materially misleading end to end,
an unprivileged actor can read/tamper with audit data, sensitive secrets are
logged, a canary breaks record boundaries, or an explicitly mandatory audit
failure causes fail-open behavior. Save event ids, redacted application and sink
records, alert timeline, negative control, retention/visibility policy, and
cleanup. A missing alert without an agreed requirement is a coverage observation.

## Remediation

Define event and alert requirements from threat models; emit structured sanitized
records with authoritative outcomes and correlation ids; protect transport,
storage, access, integrity, time, and retention; separate audit administration;
monitor pipeline health; rate-limit safely; test alerts; and document fail-open
versus fail-closed behavior for telemetry outages.

## Sources

- [OWASP A09:2025 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)

