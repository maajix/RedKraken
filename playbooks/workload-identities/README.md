---
id: modern-workload-nonhuman-identity-lifecycle
title: Workload and non-human identity lifecycle
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# Workload and non-human identity lifecycle

## Threat model

Service accounts, OAuth clients, workload identities, robots, deploy keys, API keys,
and machine certificates often outlive owners and workloads, cross environment or
tenant boundaries, receive broad standing permissions, or remain usable after
rotation, deployment removal, compromise, or ownership changes.

## Safe detection

1. Inventory each non-human principal's issuer, owner, workload, environment, tenant,
   audience, scopes/roles, credential form, issuance, rotation, revocation, and last use.
2. Trace one tester-owned workload from attestation or client authentication through
   token issuance to every relying service. Check subject/audience and environment
   binding; never exercise discovered production credentials.
3. Rotate or revoke only a tester-owned credential and verify old material stops at
   issuance, gateway, service, queue, and long-lived connection paths.
4. Remove or reassign the test workload/owner and verify credentials, sessions,
   delegated grants, cached tokens, and resources follow the documented lifecycle.
5. Record dormant, ownerless, shared, wildcard, non-expiring, cross-purpose, and
   cross-tenant principals as leads; confirm reachability and privilege before severity.

## Confirmation and evidence

Save principal and owner identifiers, issuer/audience/scope claims with values
redacted, policy decision, rotation/revocation times, old/new credential results, and
negative controls. Confirm only a lifecycle or binding invariant failure.

## Remediation

Use workload attestation and short-lived audience-bound credentials; assign an owner
and purpose; enforce least privilege and environment/tenant separation; automate
rotation, revocation, deprovisioning, and dormant-principal review; alert on anomalous
issuance and use. Avoid shared long-lived secrets.

## Sources

- [SPIFFE specification](https://github.com/spiffe/spiffe/tree/main/standards)
- [OAuth 2.0 mutual-TLS client authentication and certificate-bound tokens, RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
- [OAuth JWT assertion profiles, RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)
