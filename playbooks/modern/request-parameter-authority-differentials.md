---
id: modern-request-parameter-authority-differentials
title: Request parameter, authority, and header-construction differentials
family: http-protocol
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# Request parameter, authority, and header-construction differentials

## Threat model

Gateways, caches, frameworks, validators, and application handlers may disagree on
which value is authoritative when a name appears more than once or across path,
query, form, JSON, multipart, cookie, and header sources. First/last/list semantics,
case, nesting, encoding, type coercion, parameter merging, and method overrides can
turn a validated value into a different authorization or interpreter input.
The same disagreement affects request-target authority (`Host`, absolute-form,
Forwarded headers, TLS routing) and can let newline-bearing input cross into response
header construction, redirects, logs, email, or cache metadata.

## Safe detection

1. Map each route's documented parameter names, locations, types, cardinality, and
   authority order. Preserve the raw request and the value observed by each layer
   when authorized logs or source are available.
2. Use a read-only echo/search route or a reversible tester-owned object. Compare a
   single canary with duplicated values, changed order/case, scalar-versus-array,
   dotted/bracketed nesting, encoded delimiters, and the same name in two locations.
3. Change one representation at a time and keep request framing valid. Check proxy,
   WAF, cache key, schema validator, framework binder, authorization decision, and
   handler interpretation without attempting parser desynchronization or cache
   persistence.
4. Exercise query/form/JSON/multipart and supported method-override mechanisms only
   where the route documents or accepts them. Do not use real account identifiers,
   privileged fields, destructive actions, or high-volume parameter fuzzing.
5. Treat rejection differences and parser errors as leads. Require a deterministic
   authority mismatch with a single-value negative control before escalation.
6. Compare request-target authority, `Host`, and explicitly trusted forwarding
   headers using only an in-scope tester-owned hostname. Confirm which layer selects
   routing, reset links, redirects, and cache keys; never route to an unrelated host.
7. For response/header construction, insert an inert visible marker containing one
   encoded line-boundary variant at a time. Confirm only a new benign response header
   or split boundary in a non-cacheable tester response. Do not inject cookies,
   security headers, executable content, or a second request as the default proof.

## Confirmation and evidence

Save byte-accurate requests, content type, redirect chain, cache status, layer-
specific parsed values when available, final handler result, and matched controls.
Confirm only when two security-relevant layers select different authoritative
values and that disagreement changes authorization, validation, routing, cache, or
query behavior on synthetic data.
For authority or header construction, save the exact request target and raw header
block plus edge/application routing observations. A reflection is not confirmation;
require an unauthorized routing decision or a newly constructed response field.

## Remediation

Define one canonical schema and authoritative location for each parameter; reject
duplicates, ambiguous nesting, unexpected fields, and conflicting method overrides.
Canonicalize once before validation and authorization, pass typed values between
layers, align proxy/cache/framework parsing, and regression-test raw duplicate and
cross-location cases.
Derive authority from a configured trusted host set, configure trusted proxies
explicitly, reject conflicting authority signals, and prohibit CR/LF in any value
used to construct protocol, redirect, log, or mail headers.

## Sources

- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [OWASP WSTG v4.2: Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [CWE-235: Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
- [RFC 9112: HTTP/1.1 message parsing and field lines](https://www.rfc-editor.org/rfc/rfc9112)
- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
