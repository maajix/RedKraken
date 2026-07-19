---
id: modern-browser-policy-framing
title: Browser Security Policy, CSP, and Framing
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Browser Security Policy, CSP, and Framing

## Threat model

Treat CSP, framing, referrer, MIME, permissions, cross-origin isolation, and
transport policies as route-specific controls. Multiple headers, redirects,
caches, proxies, report-only policies, browser support, and HTML policy injection
can make the effective policy differ from the intended one.

## Safe detection

1. Collect raw headers and redirect chains for public, authenticated, error,
   download, embedded, and sensitive-action routes. Preserve duplicate headers;
   do not normalize them away before analysis.
2. Parse effective CSP directives and sources, report-only versus enforced policy,
   nonce/hash use and reuse, `base-uri`, `object-src`, `frame-ancestors`, Trusted
   Types, mixed content, and conflicts with `X-Frame-Options`.
3. Compare `Referrer-Policy`, `X-Content-Type-Options`, HSTS, Permissions Policy,
   COOP, COEP, CORP, and caching with the actual data/action sensitivity. Missing
   optional hardening alone is not an exploit.
4. Use an isolated tester-owned page to attempt framing and overlay only a benign
   read-only control; never induce a real user click. Use a harmless script/style
   canary to test policy semantics only when injection already exists.
5. Check policy differences across alternate hosts, paths, encodings, responses,
   and cache variants without persisting a shared-cache payload.

## Confirmation and evidence

Confirm when the browser enforces a materially weaker policy than declared, a
sensitive route is framed despite its requirement, or a proven injection reaches
a dangerous sink because of a policy semantic flaw. Save raw headers, effective
policy parse, browser/version, isolated page, console/network evidence, control
route, and cleanup.

## Remediation

Generate one strict route-appropriate enforced policy at the trusted edge;
preserve unique unpredictable nonces; set `frame-ancestors`; use MIME and referrer
controls; deploy Trusted Types where appropriate; remove conflicting duplicates;
test effective policy in real browsers; and keep report-only rollout separate.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Clickjacking](clickjacking.md) — severity hint: medium
- [XSSI](cors-xssi.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [OWASP WSTG: Test for Content Security Policy](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy)
- [OWASP WSTG: Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
