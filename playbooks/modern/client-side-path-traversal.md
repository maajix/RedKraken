---
id: modern-client-side-path-traversal
title: Client-Side Path Traversal into Authenticated Requests
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Client-Side Path Traversal into Authenticated Requests

## Threat model

Attacker-controlled query, fragment, route, API, or stored data can flow into a
frontend-built URL. Browser path normalization may redirect an authenticated
`fetch`/XHR to a different same-origin endpoint while preserving method, body,
headers, CSRF token, and credentials.

## Safe detection

1. From source and browser traces, map path-building inputs into `fetch`, XHR,
   navigation, imports, downloads, and worker/resource sinks.
2. Preserve the sink's real method, body, headers, and credential mode. Resolve
   dot segments and encoding layers exactly as the browser does.
3. First redirect only to a same-origin read-only canary. Then compare query,
   fragment, route, API-derived, and stored sources one at a time.
4. Test state-changing sinks only against a reversible tester-owned object and
   with destructive authorization. Do not target logout, payment, or real users.
5. Confirm the source-to-normalized-URL-to-endpoint chain in an isolated browser,
   not merely by seeing `../` accepted in JavaScript.

## Confirmation and evidence

Save the source value, data-flow/stack trace, constructed and normalized URLs,
network request with secrets redacted, reached endpoint, identity, before/after
state, browser build, and cleanup.

## Remediation

Do not concatenate untrusted values into request paths; use typed route builders
and allowlisted identifiers; reject separators and dot segments after decoding;
resolve against a fixed base and verify the final pathname; and enforce CSRF and
authorization at every destination endpoint.

## Sources

- [Doyensec CSPT2CSRF research](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)
- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [OWASP WSTG: Testing Client-Side URL Redirect](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)

