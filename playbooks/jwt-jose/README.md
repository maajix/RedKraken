---
id: modern-token-jose-verification-boundaries
title: Token and JOSE verification boundaries
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# Token and JOSE verification boundaries

## Threat model

JWT/JWS/JWE consumers fail when token type, algorithm, key, issuer, audience,
subject, client, tenant, purpose, or time claims are inferred rather than bound to
one verification context. Algorithm confusion, unsigned tokens, attacker-selected
key references, duplicate claims, weak key selection, and cross-protocol token reuse
can make a valid token authoritative at the wrong service or for the wrong purpose.

## Safe detection

1. Inventory each token producer and consumer, token type, serialization, allowed
   algorithms, issuer, audience, key source, claim requirements, clock policy, and
   intended use. Keep raw tokens out of orchestration output and evidence indexes.
2. With a tester-owned identity and non-production issuer or test fixture, establish
   a valid control, then change exactly one protected header, signature, key ID,
   issuer, audience, subject, tenant, type, purpose, or time claim.
3. Test malformed, unsigned, wrong-algorithm, wrong-key, expired, not-yet-valid,
   replayed, and duplicate-member cases as rejection tests. Do not brute-force keys,
   fetch an untrusted remote key URL, forge another user's claims, or reuse a token
   against an unrelated production service.
4. Compare authorization-code, access, ID, refresh, logout, email/action, service,
   and session tokens across consumers to detect token substitution. Confirm the
   expected token remains accepted after every isolated negative case.
5. Treat parser errors, disclosed claims, or acceptance by a generic decoder as
   leads; only the security decision of the intended consumer is authoritative.

## Confirmation and evidence

Save token fingerprints, redacted decoded structure, producer/consumer labels,
expected verification context, isolated mutation, accept/reject decision, and a
matched valid control. Confirm only acceptance of a token whose signature,
algorithm, key, type, issuer, audience, time, tenant, or purpose violates that
consumer's explicit policy.

## Remediation

Use a maintained JOSE library; configure a fixed algorithm allowlist; reject
unsecured or malformed tokens; bind keys to trusted issuers; pin or tightly
allowlist remote key locations; and require exact token type, issuer, audience,
purpose, tenant, subject, and time claims. Keep validation rules separate per token
kind and rotate/revoke keys with bounded cache behavior.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [JWT](jwt.md) — severity hint: high
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
