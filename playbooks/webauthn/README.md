---
id: modern-webauthn-passkeys
title: WebAuthn and Passkey Ceremony Boundaries
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: low
---

# WebAuthn and Passkey Ceremony Boundaries

## Signals and invariants

Test registration, authentication, passkey synchronization, device enrollment,
credential deletion, and recovery as one account-lifecycle surface. The server
must validate challenge freshness, origin, RP ID, ceremony type, credential ID,
signature, and the required user-presence/user-verification policy.

## Safe detection

1. Use isolated browser contexts and test accounts. Capture the server options
   and result for registration and authentication without recording private keys.
2. Replay a completed assertion; swap challenges, RP IDs, origins, users, or
   ceremony types one at a time; verify every mismatch fails server-side.
3. Compare passkey and password/recovery paths for weaker reauthentication,
   missing notifications, unlimited enrollment, or unauthorized deletion.
4. Exercise discoverable credentials, conditional mediation, multiple devices,
   and backed-up credentials. Treat backup eligibility/state and `signCount` as
   risk signals, not standalone authentication decisions.
5. Verify session rotation and recent-auth requirements after adding or removing
   a credential.
6. Use WebDriver virtual authenticators for repeatable negative tests: wrong or
   replayed challenge, `type`, origin, `crossOrigin`, `topOrigin`, RP ID hash,
   UP/UV flags, credential/account/user-handle binding, signature, algorithm, and
   sign-counter regression. Do not export real authenticator private keys.
7. Compare account enumeration through `allowCredentials` and error/timing
   differences. If related-origin requests are supported, fetch and validate
   `/.well-known/webauthn` and reject origins outside the declared set.

## Confirmation and evidence

Confirm only with unauthorized account access or credential lifecycle change on
a test account. Preserve redacted client-data fields, authenticator-data flags,
server options, response codes, and before/after credential inventory.

## Remediation

Follow the stable Level 2 verification algorithm completely, issue single-use
expiring challenges bound to the session and ceremony, enforce RP ID, origin,
cross-origin/top-origin and UV policy as applicable, bind credentials/user handles
to accounts, and protect enrollment/recovery with equivalent assurance. Track
Level 3 Candidate Recommendation changes separately from stable requirements.

## Sources

- [W3C Web Authentication Level 2 Recommendation](https://www.w3.org/TR/webauthn-2/)
- [W3C Web Authentication Level 3 Candidate Recommendation](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance Passkey Technical Specifications](https://fidoalliance.org/passkeys/)
