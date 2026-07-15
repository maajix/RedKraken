---
name: supply-chain-attacks
description: Tests dependency, source, build, CI/CD, artifact, registry, update, provenance, and software/data-integrity trust boundaries without publishing packages or changing production releases.
---

# Software Supply Chain & Integrity

Start with `playbooks/modern/software-supply-chain-integrity.md`. A vulnerable
version, missing signature, or unpinned reference is a lead until reachability or
a concrete integrity boundary is established.

## Attack surfaces

- Direct, transitive, vendored, runtime-downloaded, plugin, action, base-image,
  compiler, IDE, and build-tool dependencies.
- Package namespace/source confusion, mutable tags, dependency substitution,
  lifecycle scripts, installer hooks, and update-channel trust.
- Pull-request and CI trigger trust, untrusted checkout/code execution, secret
  scope, runner persistence, artifact overwrite, and promotion permissions.
- Source protections, reviewer separation, release authority, SBOM completeness,
  build provenance, artifact signatures, registry identity, and deployment
  verification.
- Deserialized/imported rules, templates, models, prompts, configuration, or
  other data whose integrity is trusted as code or policy.

## Method

1. Build a source-to-release graph: revision, workflow, builder, dependencies,
   artifact, registry, promotion, deployment verifier, and rollback.
2. Use SCA/SBOM results to find affected versions, then confirm the component is
   shipped and the vulnerable feature is reachable before calling it confirmed.
3. Review CI with an explicit trust matrix for event actor, checked-out revision,
   executed code, token/secret scope, runner, artifact namespace, and target
   environment. Use static or dry-run evidence; never execute an untrusted PR in
   a privileged pipeline.
4. Verify an existing artifact's digest, signature, identity, and provenance
   against policy. Do not sign, upload, overwrite, reserve, or publish a public
   package name as a proof.
5. Test update/import integrity only with a harness-owned registry, package,
   artifact, and disposable environment.

## Safety and evidence

Never poison public registries, push packages, modify release tags, trigger
production deployments, or expose CI secrets. Save the dependency path and
reachability proof, or the exact source-to-artifact verification gap, including
identity/digest/provenance output and a safe negative control.

