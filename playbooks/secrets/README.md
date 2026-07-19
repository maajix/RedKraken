---
id: modern-secrets-cryptographic-controls
title: Secrets, Cryptographic Controls, and Key Lifecycle
family: secrets-crypto
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Secrets, Cryptographic Controls, and Key Lifecycle

## Threat model

Map sensitive data and every key, token, certificate, nonce, and secret across
generation, storage, distribution, use, rotation, revocation, logging, and
deletion. The security boundary is the whole lifecycle, not just the chosen
algorithm.

## Safe detection

1. Scan source, history, configuration, client assets, source maps, logs, build
   output, and container layers. Validate candidate type and context locally;
   hash and redact values before storing evidence.
2. Trace each cryptographic use to its purpose. Check CSPRNG selection, token
   entropy and comparison, key/nonce/IV reuse, authenticated encryption,
   password hashing work factors, certificate/peer validation, downgrade
   behavior, and tenant/environment/purpose separation.
3. Use only tester-owned plaintext, accounts, keys, and tokens for behavioral
   tests. Compare a positive control with one changed ciphertext/tag/audience,
   expired or revoked key, wrong tenant, or wrong environment.
4. Exercise rotation/revocation on a disposable key and confirm the documented
   overlap window and failure behavior. Never rotate production keys as a test.
5. Treat a scanner match, deprecated primitive, TLS grade, entropy estimate, or
   error difference as a lead until it maps to a violated confidentiality,
   integrity, authenticity, or separation invariant.

## Confirmation and evidence

Confirm with a synthetic plaintext disclosure, accepted tampered artifact,
predictable/reused security value, cross-purpose or cross-tenant acceptance, or
verified live in-scope secret. Record location, purpose, redacted hash, exact
control pair, key state, and cleanup/revocation. Do not exercise third-party
credentials or extract real user data.

## Remediation

Use maintained cryptographic libraries and CSPRNGs; authenticated encryption;
adaptive password hashing; strict certificate, algorithm, audience, issuer, and
key-purpose validation; managed secret storage; short-lived credentials; scoped
keys; documented rotation/revocation; and automated secret scanning with rapid
revocation procedures.

## Sources

- [OWASP A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
