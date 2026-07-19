---
id: modern-software-supply-chain-integrity
title: Software Supply Chain and Artifact Integrity
family: supply-chain
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Software Supply Chain and Artifact Integrity

## Threat model

Draw the complete source-to-production graph: protected revision, dependencies,
CI trigger, checked-out code, builder, credentials, artifact, provenance,
registry, promotion, deployment verifier, update channel, and rollback. Include
data artifacts that become executable code or trusted policy.

## Safe detection

1. Generate or inspect an SBOM and reconcile direct, transitive, vendored,
   runtime-downloaded, plugin, action, base-image, and build-tool dependencies
   with the shipped artifact. A manifest-only package is not proof of reachability.
2. Check source and release protection, immutable references, reviewer separation,
   CI event/check-out mismatch, untrusted code execution before secrets, token
   scope, persistent runners, artifact namespace collisions, and environment
   promotion authority using static configuration or a disposable fork.
3. Verify an existing artifact's digest, signer identity, transparency evidence,
   and provenance subject/builder/source against an explicit policy. Verification
   must fail closed for a harmless locally modified copy.
4. Test dependency/source substitution and updater/import integrity only with a
   harness-owned namespace, registry, artifact, and isolated consumer. Never
   claim, publish, or overwrite a public package or production artifact.
5. For known vulnerabilities, record the exact dependency path, affected range,
   deployed/shipped version, reachable feature, and mitigating configuration.

## Confirmation and evidence

Confirm either a reachable affected component or a reproducible integrity-policy
failure that accepts the wrong source, identity, digest, provenance, or artifact
inside a disposable environment. Missing SBOM/signing is a maturity gap unless
the system claims or depends on that control. Save scanner output, dependency
path, CI/config lines, verification output, negative control, and cleanup.

## Remediation

Maintain complete SBOMs; pin immutable dependencies/actions/images; minimize and
monitor dependencies; isolate builds; scope ephemeral credentials; separate
review and promotion authority; generate authenticated provenance; sign artifacts;
verify identity, digest, and provenance at deployment; and stage rollouts.

## Sources

- [OWASP A03:2025 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP A08:2025 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)
- [Sigstore: verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify/)
