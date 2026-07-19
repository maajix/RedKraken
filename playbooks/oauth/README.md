---
id: modern-oauth-security-bcp
title: OAuth and OpenID Connect Security BCP
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# OAuth and OpenID Connect Security BCP

## Signals and invariants

- Authorization-code, device, refresh-token, token-exchange, or OIDC login flows.
- Bind the callback to the initiating browser session, client, issuer, redirect
  URI, PKCE verifier, and intended resource. Do not treat `state` alone as proof.
- Authorization servers compare redirect URIs exactly. Public and confidential
  clients use PKCE; `S256` is the expected challenge method.
- Resource servers validate signature, issuer, audience/resource, expiry, scope,
  and token type. One issuer's subject or email is not a global identity key.

## Safe detection

1. Capture a complete successful flow for a dedicated test account and record
   issuer, client, redirect URI, state/nonce, PKCE, resource, and token audience.
2. Repeat with one binding changed at a time: stale state, reused code, mismatched
   verifier, altered redirect, different issuer, wrong audience, and narrower
   scope. Do not forward a live token to an unrelated service.
3. Check code single-use, refresh rotation/replay handling, logout/revocation,
   authorization response issuer binding, and downgrade from PKCE `S256`.
4. Compare web, native/deep-link, and account-linking callbacks. Test only
   operator-owned redirect endpoints and accounts.
5. For device authorization, record device code, user code, client, scopes,
   expiry, polling interval, and the approval screen. Test wrong, expired,
   completed, denied, and replayed codes; client mismatch; and polling faster
   than allowed. Verify the user sees the device and requested privilege clearly.
   Never socially engineer a real user.
6. When sender-constrained tokens are advertised, replay a tester-owned DPoP
   proof with one changed method (`htm`), URI (`htu`), key/thumbprint, nonce,
   access-token hash, issued-at time, or `jti`; verify replay detection and that
   refresh-token rotation/reuse is bound to the same client or key as required.
7. Reconcile authorization-server, protected-resource, OIDC, PAR, and client
   metadata. If PAR/JAR or a high-assurance profile is advertised, verify request
   object issuer/audience/signature/expiry, request-URI one-time/client binding,
   and that front-channel parameters cannot override the pushed/signed request.

## Confirmation and evidence

Confirm only when an invalid binding yields an authenticated session, token, or
privileged resource response. Save a redacted sequence diagram, request/response
pair, token claim summary, and the single changed invariant. A permissive metadata
document without a usable bypass is an observation.

## Remediation

Implement RFC 9700, exact redirect matching, PKCE `S256`, issuer and audience
validation, one-time codes, least-privilege scopes, refresh-token replay controls,
and sender-constrained tokens where the deployment risk warrants them. Validate
DPoP proofs and pushed/signed request objects exactly; keep callback endpoints
free of open redirects and untrusted third-party content.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Attack via Google oAuth2 Playground](oauth2-attack-via-google-oauth2-playground.md) — severity hint: high
- [oAuth2](oauth2.md) — severity hint: high
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 9207: OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628.html)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html)
- [RFC 9126: OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [RFC 9101: JWT-Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
