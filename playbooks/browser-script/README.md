---
id: modern-browser-script-execution-contexts
title: Browser Script Execution Contexts
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# Browser Script Execution Contexts

## Threat model

Trace attacker-controlled data through server rendering, storage, client-side
sources, sanitizers, templates, DOM mutation, and browser parsing into an
executable HTML, attribute, URL, CSS, JavaScript, or framework sink. Reflection
alone is not XSS; the browser's final parsed context and execution decide.

## Safe detection

1. Inventory query, path, body, header, stored, cross-window, storage, and DOM
   sources. Mark every transformation and the exact final sink.
2. Start with a unique inert text canary. Preserve raw response bytes and inspect
   the live DOM to identify encoding, decoding, reparsing, and context changes.
3. Use the smallest context-specific inert break-out canary in an isolated test
   browser. Prefer a local marker such as a DOM attribute or `console` event;
   never steal cookies, tokens, clipboard data, or send data to third parties.
4. For stored paths, use a tester-owned record and viewer identity, confirm once,
   then remove it. Never expose a shared or real-user view to the canary.
5. Treat CSP, Trusted Types, and sanitizers as separate mitigation boundaries.
   Record effective browser policy and parser behavior; do not call missing CSP
   an exploitable finding without a reachable execution sink.

## Confirmation and evidence

Confirm only when controlled script semantics execute in the intended origin or
when a proven source-to-sink path makes execution deterministic. Save minimized
input, raw response, final DOM/sink, browser/version, policy console evidence,
negative control, affected identity/context, and cleanup proof.

## Remediation

Use context-appropriate output encoding; safe DOM APIs; fixed templates; strict
URL scheme handling; maintained sanitizers for intentionally accepted HTML; and
Trusted Types where applicable. Keep data out of script and event-handler
contexts. Deploy a strict nonce/hash CSP as defense in depth, not as the primary
fix, and add regression tests at the final browser sink.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Dangling Markup](dangling-markup.md) — severity hint: medium
- [XSS](xss.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP WSTG: Testing for Reflected Cross Site Scripting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [OWASP WSTG: Testing for DOM-based Cross Site Scripting](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [CWE-79: Improper Neutralization During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
