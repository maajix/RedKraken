---
id: modern-web-cache-normalization
title: Web Cache Key and URL Normalization Discrepancies
family: http-protocol
review_status: source-reviewed
reviewed_at: 2026-07-10
destructive_risk: high
---

# Web Cache Key and URL Normalization Discrepancies

## Safe detection

1. Identify cacheable public responses and authenticated dynamic responses. Use
   unique cache busters and a tester-controlled account; record `Age`, `Vary`,
   cache status, key hints, and `Cache-Control`.
2. Compare cache and origin handling of path suffixes, delimiters, encoded
   delimiters, dot segments, case, semicolons, query handling, host/forwarded
   headers, and method normalization one variable at a time.
3. Detect key discrepancies using harmless canary text or redirects on a private
   test route. Verify from a second clean tester context.
4. For deception, determine whether a dynamic test-account response is stored
   under a static-looking key. Do not lure real users or request real-user data.
5. Purge every test key when the platform supports it and record cleanup.

## Confirmation and evidence

Confirm poisoning only when a second clean context receives the tester's canary;
confirm deception only with tester-owned sensitive content. Save both request
variants, cache headers, normalized paths, second-client response, TTL, and purge.

## Remediation

Mark dynamic responses `private, no-store`, make cache rules honor origin cache
directives, normalize once and consistently, reject ambiguous paths, include every
response-varying input in the key, and never cache authenticated content by file
extension alone.

## Sources

- [PortSwigger Web Cache Deception](https://portswigger.net/web-security/web-cache-deception)
- [Gotta Cache 'em All: URL Parser Discrepancies](https://portswigger.net/research/gotta-cache-em-all)
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111.html)
