---
id: modern-http2-desync
title: HTTP Desynchronization Across Protocol Versions
family: http-protocol
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# HTTP Desynchronization Across Protocol Versions

## Preconditions

Prioritize chains with multiple HTTP parsers: CDN/WAF/load balancer to origin,
HTTP/2 or HTTP/3 at the edge with HTTP/1.1 upstream, connection reuse, connection
coalescing, or custom proxies. The bug is disagreement over request boundaries,
routing, or connection state, not the mere presence of multiple protocols.

## Safe detection

1. Record negotiated protocols and each intermediary that is known from the
   authorized architecture. Prefer a dedicated staging host or maintenance slot.
2. Test malformed-message rejection and connection closure with a self-contained
   two-request sequence tied to a unique 404 canary. Use one connection and your
   own follow-up request; never target another user's traffic.
3. Cover classic CL/TE disagreement plus CL.0, 0.CL, TE.0, malformed-chunk,
   `Expect` handling, early-response/pause behavior, HTTP/2 `content-length`
   mismatch, prohibited transfer encoding, pseudo-header/host disagreement,
   invalid field characters, downgrade normalization, and connection-locked
   routing. Change one ambiguity at a time.
4. Test front-end/back-end parser orientation in both directions and distinguish
   value-hidden versus header-hidden discrepancies. A normal response is not a
   clean bill of health when the detection gadget is cached or normalized.
5. For browser-reachable candidates, separately assess client-side desync and
   HTTP/2/3 connection coalescing with only tester-controlled origins and requests.
   Never expose unrelated browser traffic to a poisoned connection.
6. Stop at a repeatable response-queue or routing differential. Cache poisoning,
   credential capture, and cross-user impact require explicit destructive
   authorization and isolated infrastructure.

## Confirmation and evidence

Timing alone is suspected. Confirmation requires repeatable parser disagreement
or a canary response crossing only the tester's paired requests. Save raw bytes or
frames, protocol negotiation, connection boundaries, timestamps, and responses.

## Remediation

Use HTTP/2 or later upstream where supported; otherwise enable strict normalization
at every hop, reject malformed or ambiguous messages and close the connection,
validate fields before downgrade, avoid rewriting framing, and disable backend
reuse only as temporary impact reduction.

## Sources

- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [HTTP/1.1 Must Die: the Desync Endgame](https://portswigger.net/research/http1-must-die)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [PortSwigger HTTP Request Smuggling Research](https://portswigger.net/research/request-smuggling)
