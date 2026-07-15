---
id: modern-identity-provisioning-role-lifecycle
title: Identity Provisioning, Invitations, Groups, and Deprovisioning
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Identity Provisioning, Invitations, Groups, and Deprovisioning

## Threat model

Model invitations, self-signup, JIT/SCIM provisioning, account linking, domain
discovery, IdP/group/role mapping, tenant moves, suspension/deletion, rehire,
email/identifier reuse, service accounts, sessions/tokens, owned resources, and
asynchronous directory synchronization as one lifecycle state machine.

## Safe detection

1. Use two synthetic tenants/directories and tester-owned identities. Draw the
   identity graph linking external issuer/subject, SCIM id/externalId/userName,
   email, local account, tenant, groups, roles, sessions, tokens, and resources.
2. Exercise create/invite/accept, duplicate, resend, expire, revoke, JIT versus
   pre-provisioned login, update, group add/remove, disable, delete, restore and
   identifier reuse one transition at a time.
3. Reorder or replay stale invitation/provisioning operations and compare API,
   SSO, UI, batch and async sync paths. Bind each operation to issuer, tenant,
   account, intended role, actor, purpose, expiry and current lifecycle version.
4. After group removal, suspension or deletion, verify existing sessions, refresh
   tokens, API keys, app passwords, device grants, sharing links, jobs and cached
   entitlements lose access within the documented window.
5. Check last-owner/admin and resource-transfer invariants with disposable
   resources. Do not delete production identities or trigger a real enterprise
   directory sync.

## Confirmation and evidence

Confirm cross-tenant/account linking, unintended role/group assignment, accepted
stale/revoked lifecycle operation, or retained access after authoritative
deprovisioning on tester identities. Save identity graph with opaque labels,
ordered transitions, directory/app states and timestamps, sessions/tokens tested,
resource ownership, negative control, and cleanup.

## Remediation

Key external identities by exact issuer and immutable subject; validate SCIM
schemas and tenant ownership; make lifecycle operations versioned, idempotent and
actor/purpose bound; centralize group/role mapping; expire invitations; revoke all
credential/session types on deprovisioning; enforce last-owner/resource-transfer
invariants; and continuously reconcile directory and application state.

## Sources

- [RFC 7643: SCIM Core Schema](https://www.rfc-editor.org/rfc/rfc7643.html)
- [RFC 7644: SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)

