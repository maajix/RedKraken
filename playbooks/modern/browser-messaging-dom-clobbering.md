---
id: modern-browser-messaging-dom-clobbering
title: Browser Messaging, DOM Clobbering, and Persistent Client Control
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Browser Messaging, DOM Clobbering, and Persistent Client Control

## Safe detection

1. Inventory `postMessage`, `MessageChannel`, iframe, worker, service-worker, and
   broadcast-channel senders and receivers. Record sender origin/source, expected
   message schema, destination origin, and every privileged sink reached.
2. From an operator-controlled origin, vary origin and source independently.
   Reject wildcard, suffix/substring, scheme-confused, opaque `null`, navigated-
   window, and trusted-but-compromisable sibling assumptions. Validate message
   structure before dispatch and authorize the requested action server-side.
3. Where sanitized HTML is accepted, test whether `id`/`name`, forms, anchors,
   iframes, or named properties can replace a JavaScript object or DOM API result.
   Follow the clobbered value only to a benign sink canary.
4. Trace attacker-influenced URLs into script/resource creation,
   `serviceWorker.register()`, `importScripts()`, navigation, HTML insertion, or
   privileged messages. Inspect service-worker scope and update behavior; use an
   isolated profile and unregister every test worker during cleanup.
5. Test CSP as mitigation evidence, not as proof of safety. Check whether a nonce-
   trusted script, form destination, or worker gadget turns HTML injection into
   script execution or persistent response control.

## Confirmation and evidence

Confirm with a tester-origin message causing an unauthorized read/action, or a
clobbered value reaching a harmless executable/resource canary. Save the page and
frame origins, source-window identity, message, stack/data-flow trace, DOM before
and after, worker registrations/scopes, browser build, and cleanup.

## Remediation

Use exact origins and verify both `event.origin` and `event.source`; use typed
message schemas and capability-minimal handlers; avoid named-window/DOM globals;
keep sanitized markup away from configuration; resolve resource URLs from trusted
constants; constrain service-worker scope; and deploy strict CSP as defense in
depth.

## Sources

- [OWASP WSTG: Testing Web Messaging](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging)
- [HTML Standard: cross-document messaging](https://html.spec.whatwg.org/multipage/web-messaging.html)
- [PortSwigger DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [Bypassing CSP via DOM Clobbering](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [Hijacking Service Workers via DOM Clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)

