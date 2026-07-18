---
id: modern-attack-surface-architecture-mapping
title: Reviewed attack-surface and architecture mapping
family: config-iac
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: low
---

# Reviewed attack-surface and architecture mapping

## Threat model

Security testing misses controls when the observed route list is not reconciled with
hosts, trust zones, identities, protocols, data flows, third parties, and deployed
versions. A scanner result is an observation, not a complete architecture model.

## Safe detection

1. Inventory authorized domains, resolved addresses, certificates, virtual hosts,
   ports, application routes, APIs, realtime channels, jobs, callbacks, and static
   assets. Preserve discovery source and observation time.
2. Build data-flow and trust-zone edges for browser, edge/CDN, gateway, application,
   datastore, queue, identity provider, outbound fetcher, and administrative plane.
3. Reconcile passive evidence, live bounded discovery, schemas, client bundles, and
   authorized deployment/source manifests. Record disagreements as leads.
4. Repeat targeted mapping after new schemas, identities, hosts, or technologies are
   found. Stop at the configured budget or when normalized surface delta is zero.
5. Mark each expected surface `observed`, `not-applicable`, `blocked`, or `not-tested`
   with evidence. Do not infer absence from one failed tool.

## Confirmation and evidence

Save a normalized node/edge inventory, discovery provenance, scope decision, surface
delta by round, and unresolved discrepancies. A confirmed mapping gap requires an
authorized expected surface that is absent from controls or an observed surface not
represented in the declared architecture—not merely an unfamiliar banner.

## Remediation

Maintain an owner-reviewed asset and data-flow inventory; reconcile it with DNS,
certificates, gateways, schemas, deployment manifests, and monitoring. Retire stale
routes and require security review for new trust-zone or third-party edges.

## Sources

- [OWASP WSTG v4.2 Information Gathering](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/README)
- [NIST SP 800-115 Technical Guide to Information Security Testing](https://csrc.nist.gov/pubs/sp/800/115/final)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
