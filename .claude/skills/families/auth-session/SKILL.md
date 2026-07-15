---
name: auth-session-attacks
description: Triage and exploit authentication, session, and identity flaws — JWT, oAuth2, SAML, session/cookie handling, sign-up/login/register logic, password reset, type juggling auth bypass, predictable UUIDs/tokens, and auth rate-limit bypass. Use when the target has login, tokens, SSO, or account flows.
---

# Auth & Session Family

Covers: **JWT**, **OAuth2/OIDC including device flow**, **SAML**,
**WebAuthn/passkeys**, **MFA/recovery/session lifecycle**, **identity-parser
differentials**, **cookie-parser differentials**, **session/cookie** handling,
**Sign Up/Login/Register** logic, **Password Reset**, **Type Juggling** (auth
bypass), **UUID/token predictability**, **rate-limit bypass** on auth. Read
matching `playbooks/modern/` cards before the imported
`playbooks/web/_catalog.md`. Obey `scope-guard` + `tool-preflight`.

## Signals → technique

| Signal | Try |
|--------|-----|
| `Authorization: Bearer eyJ...` | JWT attacks |
| SSO redirect, `SAMLResponse=`, `id_token` | SAML / oAuth2 |
| `Set-Cookie` session id, `remember me` | session fixation/prediction, cookie tampering |
| registration / login / reset flows | logic flaws, user enumeration, weak password policy |
| `==` loose-compare languages (PHP), magic-hash tokens | type juggling |
| sequential/guessable ids or reset tokens | IDOR / token prediction |

## Approach

1. **JWT.** Decode; check for `alg:none`, RS256→HS256 confusion (sign with public key as HMAC secret), unverified signature, weak secret (`jwt-tool <jwt> -C -d wordlist`), `kid` injection/SQLi/path traversal, `jku`/`x5u` SSRF. `jwt-tool -M at -t <url> -rh "Authorization: Bearer <jwt>"` for the automated test matrix. Binary is **`jwt-tool`** (hyphen); some notes write `jwt_tool` — invoke as `jwt-tool`. (Tool missing → notify per `tool-preflight`.)
2. **OAuth2 / SAML.** redirect_uri abuse / open redirect → token theft, `state` CSRF, missing audience/signature checks, SAML signature stripping / XML signature wrapping, parser round trips, namespace/canonicalization confusion, IdP-confusion. Load `oauth-security-bcp.md` and `identity-parser-differentials.md`; for SAML, require the application to consume exactly the signed node.
3. **Session and cookies.** Fixation (does the id rotate on login?), predictable/insecure cookies, missing `HttpOnly/Secure/SameSite`, logout not invalidating server-side. When duplicate, quoted, legacy, or prefixed cookies appear, load `cookie-parser-differentials.md` and compare browser/edge/framework parsing with canary cookies before touching a session.
4. **Account flows.** user enumeration (response/timing diffs — pair with `race-conditions`), password-reset token leakage/predictability/host-header poisoning, registration overwrite, mass assignment.
5. **Type juggling.** PHP `==` `0e...` magic hashes, `strcmp` array bypass — for login/token checks.
6. **Identity parsing.** Map email/claim values through validator, IdP, storage,
   tenant mapping, and delivery. Test canonicalization collisions only between
   tester-owned identities; never use an email-domain suffix as proof of trust.
7. **Device flow.** Test code expiry/reuse, client binding, polling interval,
   approval/denial, scope display, and cross-device identity only with a
   tester-controlled device and account.
8. **MFA/recovery/session parity.** Load
   `authentication-mfa-recovery-lifecycle.md`; map alternate channels and test
   step, account, session, purpose, expiry, recent-auth, rotation, and revocation
   bindings with two tester accounts.

## Evidence
Capture the token/cookie before & after, the forged artifact, and the privileged response proving takeover/bypass. Account-takeover PoC against real users needs `destructive_allowed`; otherwise demonstrate on a test account from `test_credentials`.
