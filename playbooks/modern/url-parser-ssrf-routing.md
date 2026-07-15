---
id: modern-url-parser-ssrf-routing
title: URL Parser Differentials, Redirects, and SSRF Routing
family: ssrf-xxe-file
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# URL Parser Differentials, Redirects, and SSRF Routing

## Threat model

URL validation fails when the validator, redirect handler, DNS resolver, proxy,
and final client disagree on scheme, authority, host, port, address, or path. Map
each interpretation instead of treating an allowlist regex as the security
boundary.

## Safe detection

1. Start with a unique URL on the engagement's approved OOB host and record the
   request method, headers, body, source address, redirect behavior, and DNS
   resolution. Use a dedicated canary per input.
2. Compare standards-valid parser edge classes one at a time: userinfo and `@`,
   backslashes, encoded delimiters, fragments, empty or multiple ports, trailing
   dots, Unicode/IDNA, IPv4 alternate forms, IPv4-in-IPv6, and scheme-relative or
   apparently relative URLs. Generate cases for the observed parser pair rather
   than spraying a generic list.
3. Test redirect handling with an operator-controlled chain. Revalidate scheme,
   host, port, resolved addresses, and policy on every hop; test method and header
   carry-over separately. Bound chain length and stop before resource exhaustion.
4. Test DNS rebinding only with an operator-controlled domain and a harmless
   in-scope listener. Verify all resolved addresses before connecting and pin the
   approved result for the lifetime of the request.
5. Use synthetic loopback/internal fixtures. Access to cloud metadata, control
   planes, credentials, or other tenants requires explicit RoE authorization; do
   not pivot from a callback automatically.

## Confirmation and evidence

Confirmation requires a mismatch between the validated destination and the
actual connected destination, or an unauthorized response from a tester-owned
internal fixture. Save the raw input, each parser's normalized URL, redirect
trace, DNS answers with timestamps, connection destination, and OOB event.

## Remediation

Use one standards-conforming URL parser; allowlist schemes and exact destinations;
reject credentials and ambiguous authorities; resolve and classify every address;
block local, private, link-local, multicast, and special ranges as appropriate;
revalidate every redirect; pin the validated address; and enforce egress policy
independently of application validation.

## Sources

- [RFC 3986: URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger URL Validation Bypass Cheat Sheet research](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet)
- [PortSwigger maintained URL bypass data](https://github.com/PortSwigger/url-cheatsheet-data)

