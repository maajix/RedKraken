---
name: config-iac-attacks
description: Tests deployment, cloud, container, infrastructure-as-code, API inventory/resource, error handling, and security-observability configuration boundaries with passive or bounded probes.
---

# Configuration, Deployment & API Posture

Load the matching reviewed topic: `playbooks/deployment/README.md`,
`playbooks/api/README.md`, or `playbooks/logging/README.md`.
Use `playbooks/information-disclosure/README.md` for source maps, backups, stack
traces, build/debug metadata, or cross-context response leakage.
Configuration and version fingerprints are leads; confirm an exposed capability,
data disclosure, policy bypass, unsafe consumption path, or missing control.

## Attack surfaces

- Default/sample/admin/debug endpoints, directory listing, backups, source maps,
  verbose errors, unnecessary methods/services, insecure headers and cross-origin
  policies, and environment drift.
- Cloud IAM/storage/network exposure, public control planes, metadata access,
  container privilege/mounts/capabilities, orchestration policy, Terraform and
  deployment manifests, and CI configuration.
- Shadow, beta, deprecated, alternate-host and undocumented APIs; stale schemas;
  inconsistent auth across versions; debug/management endpoints.
- Per-request and aggregate resource ceilings, pagination/export/search/upload
  costs, GraphQL/query complexity, async jobs, third-party API trust, redirects,
  timeouts, schema validation, and response handling.
- Security-event coverage, log injection/tampering, sensitive log data, alert
  delivery, correlation, rate controls, retention, clock/order, and fail-closed
  behavior when telemetry is unavailable.

## Method and safety

1. Compare declared IaC/configuration with the deployed, in-scope behavior and
   record the effective identity, network, storage, runtime, and API policies.
2. Use passive headers/schema/version discovery and one bounded canary request
   before any mutation. Do not enumerate cloud assets outside the named scope.
3. For resource controls, prove missing per-request bounds with the smallest
   synthetic input that crosses a documented limit. Load, flood, recursive,
   decompression-bomb, and cost-amplification testing requires explicit
   availability authorization.
4. For third-party consumption, substitute only a harness-owned provider and use
   benign malformed/redirected responses. Never compromise or impersonate a real
   supplier.
5. For logging, generate unique synthetic events in a test tenant and confirm the
   complete event-to-alert path with the operator. Do not erase or forge
   production audit history.

Save declared and effective configuration, exact bounded probe, authoritative
after-state, event/alert correlation identifier, and cleanup. Missing best
practice alone is not a confirmed exploit unless the engagement accepts
hardening findings.
