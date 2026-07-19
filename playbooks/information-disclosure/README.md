---
id: modern-information-disclosure-debug-artifacts
title: Information Disclosure and Debug Artifact Exposure
family: config-iac
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Information Disclosure and Debug Artifact Exposure

## Threat model

Inventory information exposed through normal/error responses, headers, comments,
client bundles and source maps, build metadata, manifests, schemas, backups,
temporary files, directory indexes, diagnostics, metrics, health/debug/admin
routes, logs, caches, and cross-user or cross-tenant response mix-ups.

## Safe detection

1. Passively inspect shipped assets, metadata, schemas, robots/sitemaps, response
   headers, common advertised files, and links found in the application. Do not
   brute-force broad filenames or neighboring hosts by default.
2. Send one harmless malformed, missing, extra, wrong-type, wrong-media-type, or
   unsupported-method value at a time to a tester-owned route. Compare production
   and alternate route/version behavior without repeated fault generation.
3. Reconcile source-map references and build artifacts with deployed files. Store
   only the minimum excerpt needed and redact credentials, personal data, source,
   stack paths, or internal hostnames that are not essential to the finding.
4. Verify whether disclosed versions, identifiers, paths, schemas, or tokens
   materially enable another in-scope boundary violation. A banner alone is
   usually inventory, not a vulnerability.
5. Test cross-user/tenant response leakage only with two tester identities and
   unique canaries; avoid shared-cache persistence or real-user identifiers.

## Confirmation and evidence

Confirm direct unauthorized sensitive data/source/config/secret disclosure, or a
minimal proven chain where disclosed information crosses another security
boundary. Save exact request or artifact URL/path, response hash and redacted
excerpt, identity/cache context, control response, chain evidence, and cleanup.

## Remediation

Remove debug and unused artifacts from production builds; centralize minimal error
handling; disable indexing; protect diagnostics and schemas; strip source maps or
restrict them; prevent secrets in client/build/log output; set private/no-store
where required; and continuously scan deployment artifacts before release.

## Sources

- [PortSwigger Web Security Academy: Information disclosure](https://portswigger.net/web-security/information-disclosure)
- [OWASP WSTG: Testing for Error Code](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling)
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
