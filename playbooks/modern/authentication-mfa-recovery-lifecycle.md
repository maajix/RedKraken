---
id: modern-authentication-mfa-recovery-lifecycle
title: Authentication, MFA, Recovery, and Session Lifecycle
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Authentication, MFA, Recovery, and Session Lifecycle

## Threat model

Model password, passwordless/magic-link, MFA, recovery, remembered-device,
account-linking, sensitive-action reauthentication, session, and support-assisted
paths as one assurance graph. The weakest alternate channel defines the real
account security level.

## Safe detection

1. Use two test accounts and enumerate every web, mobile, API, federated, legacy,
   recovery, enrollment, step-up, and support path. Record required factors and
   the session state before and after each transition.
2. Attempt step skipping, direct navigation, stale transaction reuse, factor or
   account swapping, alternate endpoint/method/media type, and completion from a
   different browser session. Change one binding at a time.
3. Test recovery and backup codes for entropy only by design/source evidence or a
   tiny bounded tester-owned sample; verify expiry, single use, account/session
   binding, low-count rate limits, invalidation, and notifications.
4. Compare factor enrollment/removal, password/email/phone changes, key export,
   and other sensitive actions for recent-auth and equal-assurance requirements.
5. Verify session rotation on authentication/privilege change, logout and reset
   invalidation, concurrent-session visibility/revocation, absolute/idle timeout,
   and remembered-device revocation using only tester sessions.

## Confirmation and evidence

Confirm only when a changed/skipped factor or lifecycle binding yields a session,
account change, or sensitive action, or when a revoked/expired tester session
remains usable contrary to policy. Record the assurance graph, exact transition,
two-account/session labels, before/after state, notification, and cleanup. Avoid
user lockout and never brute-force real accounts.

## Remediation

Centralize authentication state transitions; bind each transaction to account,
session, purpose, channel, and expiry; require equal assurance across alternate
paths; make codes single-use and rate-limited; rotate/invalidate sessions on
security changes; require recent authentication; notify users; and offer complete
session/factor inventory and revocation.

## Sources

- [OWASP WSTG: Testing Multi-Factor Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
- [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [NIST SP 800-63B-4: Authentication and Authenticator Management](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)

