---
id: modern-browser-realtime-xsleaks
title: WebSocket, WebTransport, and Cross-Site State Leaks
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-10
destructive_risk: medium
---

# WebSocket, WebTransport, and Cross-Site State Leaks

## Safe detection

1. Capture WebSocket/WebTransport endpoints, origin, subprotocol, authentication,
   reconnect behavior, and per-message schemas in an isolated browser context.
2. Test WebSocket handshakes from an untrusted Origin using a test session. Check
   authentication at connect and authorization for every message or subscription.
3. Verify expiry/logout closes long-lived sessions; reconnect cannot reuse stale
   credentials; message IDs/nonces prevent unauthorized replay; limits cover
   frames, streams, datagrams, compression, backpressure, and idle connections.
4. For WebTransport, verify the server filters `Origin`, establishes identity
   in-band, and applies policy independently to streams and datagrams. It does not
   automatically carry cookies or HTTP authentication.
5. Look for cross-site account-state or search-result oracles through navigation,
   load/error events, window properties, cache probing, resource dimensions, or
   timing. Use two tester-controlled account states and repeat to reduce noise.

## Confirmation and evidence

Confirm CSWSH with an unauthorized test-origin action/read, and an XS-Leak with a
repeatable bit of private tester state above a documented noise threshold. Save
origin/session state, redacted frame metadata, trials, controls, and browser build.

## Remediation

Allowlist Origins, use explicit anti-CSRF/session binding, authorize every
message, expire live connections, bound resources, deploy Fetch Metadata and
cross-origin isolation where appropriate, and make cross-site responses uniform.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [WebSocket Attacks](websocket-attacks.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [W3C WebTransport](https://www.w3.org/TR/webtransport/)
- [XS-Leaks Wiki](https://xsleaks.dev/)
- [OWASP XS Leaks Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html)
