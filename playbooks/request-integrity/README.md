---
id: modern-browser-request-integrity-policy
title: Browser request integrity, CSRF, CORS, and Fetch Metadata
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# Browser request integrity, CSRF, CORS, and Fetch Metadata

## Threat model

Cookie-authenticated actions and sensitive cross-origin responses fail when the
server treats ambient credentials, `Origin`/`Referer`, CORS, SameSite cookies,
CSRF tokens, or Fetch Metadata as interchangeable controls. Redirects, simple
requests, method overrides, alternate content types, sibling origins, and route-
specific middleware can produce a weaker effective policy than intended.

## Safe detection

1. Inventory state-changing and sensitive read routes, their authentication mode,
   accepted methods/content types, cookie SameSite policy, CSRF mechanism, CORS
   response, and Fetch Metadata decision. Include error and alternate-host routes.
2. With a tester-owned identity and reversible object, replay a harmless request
   while changing one signal at a time: CSRF token, `Origin`, `Referer`,
   `Sec-Fetch-Site`, method, content type, redirect path, or duplicate header.
3. From an isolated tester-owned origin, distinguish whether the browser can send
   the request from whether script can read the response. Test simple and
   preflighted forms separately; never infer CORS impact from headers alone.
4. Check login, logout, token refresh, account linking, upload, GraphQL, RPC, and
   method-override routes for policy drift. Use only synthetic data and avoid
   actions involving another user, money, messages, or irreversible state.
5. Confirm the intended same-origin request still succeeds as a matched control.
   Missing defense-in-depth headers without an exploitable browser path are leads.

## Confirmation and evidence

Save the initiating origin, browser/version, request and response headers, cookie
attributes with values redacted, preflight result, before/after state, negative
control, and cleanup. Confirm CSRF only when a cross-site browser request causes an
unauthorized state transition; confirm CORS impact only when an unauthorized origin
can read a response containing data or capability it should not receive.

## Remediation

Use an unpredictable session-bound CSRF token or a framework's equivalent on every
state change; validate request origin; use SameSite as defense in depth; reject
unexpected Fetch Metadata contexts; and keep safe methods free of state changes.
Allowlist exact CORS origins, methods, and headers, vary caches on `Origin`, and
never combine credentialed access with arbitrary reflected origins.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [CORS](cors.md) — severity hint: medium
- [CSRF](csrf.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [WHATWG Fetch: HTTP CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [W3C Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP WSTG v4.2: Testing for Cross-Site Request Forgery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
