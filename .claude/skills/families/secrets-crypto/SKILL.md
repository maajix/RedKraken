---
name: secrets-crypto-attacks
description: Tests secret exposure, cryptographic misuse, weak randomness, key lifecycle, transport/data protection, and integrity-verification boundaries in source, configuration, artifacts, and web behavior.
---

# Secrets & Cryptographic Controls

Start with `playbooks/modern/secrets-cryptographic-controls.md`. Treat scanner
matches, algorithm names, and TLS configuration as leads: confirmation requires a
real protection failure involving in-scope synthetic data or a verified live
credential. Never send discovered credentials to third-party services.

## Attack surfaces

- Secrets in source/history, environment/config, client bundles, source maps,
  logs, errors, backups, build artifacts, container layers, and CI output.
- Predictable security tokens, nonces, reset links, identifiers, CSRF values, or
  verification codes caused by weak randomness or unsafe comparison.
- Missing, weak, downgradable, unauthenticated, or incorrectly composed
  encryption; nonce/IV reuse; padding/error/timing oracles.
- Key confusion, insecure defaults, missing rotation/revocation, cross-purpose or
  cross-tenant key reuse, and verifier/protocol disagreement.
- Sensitive data sent or stored in cleartext, cacheable responses, insecure
  cookies, or channels without correct peer/certificate validation.

## Method

1. Inventory sensitive data and each secret/key's producer, store, consumer,
   purpose, tenant, environment, rotation path, and revocation path.
2. Use `gitleaks`, `trufflehog`, and `trivy` as discovery aids, then validate
   context, scope, liveness, and privilege without exercising third-party access.
3. For randomness, collect only a bounded sample of tester-owned values and look
   for deterministic reuse or a source-level weak generator. Statistical noise
   alone is not a finding.
4. Test crypto boundaries with synthetic plaintext and keys. Require observable
   confidentiality, integrity, authenticity, or separation failure; an old
   primitive name without a security-sensitive use remains a lead.
5. Verify lifecycle controls using tester-owned keys: rotate or revoke one and
   confirm old material stops working where the protocol promises it should.

## Safety and evidence

Redact secret values while retaining a stable hash, type, location, owner, and
validation result. Do not crack production password hashes, decrypt real user
data, or exploit padding/timing oracles beyond a one-bit synthetic proof without
explicit destructive authorization. Save the exact source/config location or
request pair, protection invariant, negative control, and cleanup/revocation.

