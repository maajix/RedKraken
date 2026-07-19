---
id: modern-http2-desync
title: HTTP Request Smuggling and Desynchronization
family: http-protocol
review_status: source-reviewed
reviewed_at: 2026-07-19
destructive_risk: high
---

# HTTP Request Smuggling and Desynchronization

This is the reviewed entrypoint for HTTP request smuggling, response
desynchronization, and closely related connection-state attacks. It is
source-checked through 2026-07-19 against the HTTP RFCs and the current James
Kettle/PortSwigger research sequence, including *HTTP/1.1 Must Die* and HTTP
Request Smuggler 3.x.

The durable lesson from the 2025 research is that matching known CL/TE payloads
is not enough. Look for the root cause: two components disagreeing about which
fields exist, where a message ends, when a response is complete, or which
request owns connection state.

## Preconditions and architecture map

Prioritize chains with two or more HTTP processors: CDN, WAF, load balancer,
reverse proxy, service mesh, gateway, forward proxy, cache, application server,
or custom protocol adapter. Record for every hop:

- client protocol and ALPN result, including hidden HTTP/2 support;
- upstream protocol between each intermediary and the origin;
- HTTP/2-to-HTTP/1.1 downgrade or h2c upgrade behavior;
- request normalization, dechunking, header insertion/removal, and method/body
  policy;
- upstream pooling, client-to-upstream affinity, and cross-user reuse;
- first-request routing, HTTP/2+ connection coalescing, caching, and retry
  behavior.

Do not infer safety from HTTP/2 or HTTP/3 at the edge. End-to-end HTTP/2+
removes HTTP/1.1 framing ambiguity; an HTTP/1.1 upstream hop brings the risk
back, and downgrade adds HTTP/2-exclusive injection inputs.

## State-of-the-art coverage matrix

| Surface | Required coverage | Key distinction |
|---|---|---|
| Classic HTTP/1.1 framing | CL.CL, CL.TE, TE.CL, TE.TE and duplicate/obfuscated framing fields | Which hop honors each `Content-Length` or `Transfer-Encoding` value? |
| Body ignored by one hop | CL.0, H2.0, TE.0 | One component forwards or frames a body that the next component treats as a new request. |
| Reverse orientation | 0.CL, including early-response gadgets and double-desync conversion to CL.0 | The front end sees no body while the back end waits for one; ordinary cases deadlock until an early response breaks it. |
| Chunk parser differentials | malformed chunks, dechunk/rechunk behavior, TERM.EXT, EXT.TERM, TERM.SPILL, SPILL.TERM, trailer, and line-length disagreement | Modern variants can avoid a CL-versus-TE conflict entirely. |
| Interim/early responses | `Expect: 100-continue`, obfuscated `Expect`, HEAD/body rules, multiple 1xx blocks, early final responses | Disagreement can desync requests or responses, bypass response-header removal, or expose stale memory. |
| Timeout state | pause-based desync and partial-request behavior | Requires a client timeout longer than the target timeout; test only in isolation. |
| HTTP/2 downgrade | H2.CL, H2.TE, H2.0, prohibited field forwarding, CR/LF injection, pseudo-header and request-line injection | HTTP/2 framing is unambiguous, but an unsafe rewrite can synthesize an ambiguous HTTP/1.1 stream. |
| HTTP/2 exploitation | request splitting, response-queue poisoning, request tunnelling, hidden HTTP/2 | Tunnelling may remain exploitable without upstream connection reuse. |
| Upgrade/tunnel paths | h2c upgrade smuggling and other hop-by-hop upgrade handling | A front end may forward an upgrade it does not understand and expose a raw back-end tunnel. |
| Optimistic protocol transitions | rejected HTTP/1.1 `CONNECT`/`Upgrade` with post-transition bytes sent before acceptance | On rejection, optimistic bytes may become authenticated HTTP/1.1 requests; RFC 9931 standardized mitigations in 2026. |
| Browser-powered attacks | client-side desync (CSD), browser-compatible CL.0, pause-based delivery | These poison a browser-to-server HTTP/1.1 connection and can affect single-server sites. |
| Connection state | connection-locked smuggling, first-request validation/routing, host/TLS state reuse | Similar impact, but first-request routing and other state attacks are not necessarily request smuggling. |
| HTTP/2/3 coalescing | cross-origin connection reuse plus first-request routing | Connection contamination is adjacent to desync; use tester-owned sibling origins only. |

### Parser-discrepancy-first detection

HTTP Request Smuggler 3.x compares a mutated header with controls such as the
normal header, an absent/renamed header, and a similarly mutated irrelevant
header. A unique response for only the mutated real header is evidence that the
server chain parses it inconsistently. Apply multiple headers, mutations, and
control strategies; a single status-code difference is a lead, not proof.

Classify promising discrepancies before attempting a framing attack:

- **V-H (visible-hidden):** the mutated field is visible to the front end but
  hidden from the back end. A hidden `Content-Length` can yield CL.0; a hidden
  `Transfer-Encoding` can yield TE.CL.
- **H-V (hidden-visible):** the field is hidden from the front end but visible
  to the back end. This can yield CL.TE/header smuggling or 0.CL. The 2025
  research showed that 0.CL can be exploitable using an early-response gadget
  followed by a double desync.

Response provenance matters more than the numeric status: distinguish edge and
origin behavior using banners, headers, body templates, timing, and known
architecture. Also retain discrepancies that only show risky parsing on a
single server; placing that server behind a differently lenient proxy may make
the chain exploitable.

## Safe detection

1. Confirm written authorization explicitly covers desync testing. On shared
   production, exclude cache poisoning, response-queue poisoning, credential
   capture, CSD delivery, pause/timeout manipulation, and cross-user effects
   unless separately authorized.
2. Establish harmless baselines for HTTP/1.1 and HTTP/2. Check ALPN and also
   test authorized hidden HTTP/2 support. Use unique, non-cacheable canary paths
   owned by the tester.
3. Run parser-discrepancy probes with matched controls. Change only one header,
   mutation, protocol, or method at a time. Rate-limit probes and stop on
   elevated errors, connection churn, or collateral responses.
4. Test the matrix above in both parser orientations. Prefer CL.0-style
   self-contained confirmation over TE-based attacks when both model the same
   discrepancy, because it is less likely to be altered by a WAF. Repeat the
   same probe across cache hit/miss, redirect/error, and routing branches;
   fast-path code may consume a body differently from the normal path.
5. By default, disable **client-side** connection reuse between the attack and
   follow-up request (`requestsPerConnection=1`). Use two tester requests with
   an unpredictable canary so a result cannot be explained by the client's own
   HTTP pipelining.
6. Treat timing, a timeout, a `400`, or two responses on one reused client
   connection as suspected only. Confirm with repeatable parser disagreement or
   a canary crossing only the tester's independently issued requests.
7. If a result exists only with client connection reuse, investigate the three
   legitimate exceptions separately: connection-locked request smuggling,
   connection-state attacks, and client-side desync. Prove server-side impact;
   an attacker merely receiving their own surprising response is insufficient.
8. Stop at the lowest-impact proof. Do not capture unrelated requests or
   responses. A tester-controlled nested HTTP/1 response inside an HTTP/2
   response can be strong evidence without involving another user.

`Expect`, 0.CL double-desync, pause-based probes, response concatenation, and
automated exploit generation can disturb pooled connections or surface memory.
Use them only on isolated infrastructure or with explicit high-risk approval.
The imported notes below contain payload depth but remain unreviewed; recalculate
all message lengths and validate every command before use.

## Confirmation and evidence

Save enough wire-level evidence for another tester to distinguish the finding
from ordinary keep-alive:

- exact raw HTTP/1.1 bytes or HTTP/2 frames/Inspector fields;
- ALPN, client protocol, inferred upstream protocol, connection IDs, reuse
  settings, and request ordering;
- the baseline and every matched parser-discrepancy control;
- unique canary values, timestamps, responses, and repeat count;
- which component likely generated each response and why;
- a statement that only tester-owned requests were affected;
- the smallest demonstrated impact and the authorization needed for any higher
  impact chain.

Timing alone is not confirmation. A valid report should identify the parser or
state disagreement and show how it crosses the intended security boundary.

## Tooling

- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
  is the primary maintained Burp extension. Version 3.x adds root-cause parser
  discrepancy detection alongside HTTP/1.1, HTTP/2 downgrade, tunnelling,
  client-side desync, pause, and connection-state probes.
- [HTTP Request Smuggler BApp page](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
  records the packaged version and current feature set.
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) provides the
  low-level request sequencing used by generated PoCs and the 0.CL offset
  helper. Keep `requestsPerConnection=1` unless testing a documented
  connection-locked case.
- [Smuggling or pipelining?](https://github.com/PortSwigger/bambdas/blob/main/CustomAction/SmugglingOrPipelining.bambda)
  is a PortSwigger Repeater custom action for triaging nested-response false
  positives. It supports analysis; it does not replace an impact proof.
- [Web Security Academy request-smuggling labs](https://portswigger.net/web-security/request-smuggling)
  provide isolated practice for classic, HTTP/2, browser, and 0.CL techniques.
- [smugchunks](https://github.com/JeppW/smugchunks) covers chunk-body parser
  differentials that do not overlap traditional CL/TE scanners. Findings still
  require manual controlled confirmation.
- [HTTP Garden](https://github.com/narfindustries/http-garden) supports
  differential testing across HTTP implementations when source or a local
  deployment is available.
- [HTTP Anomaly Rank](https://portswigger.net/research/introducing-http-anomaly-rank)
  is integrated into current Turbo Intruder/Burp APIs and can surface subtle
  response outliers in large parser-probe sets. It is a triage aid, not proof.

## Remediation

The durable fix is **HTTP/2 or later on every upstream hop**, not merely between
the browser and edge. Eliminate HTTP/2-to-HTTP/1.1 downgrade and unnecessary
protocol translation. Then verify the deployed path rather than trusting a
configuration flag.

Where an HTTP/1.1 upstream remains:

- enable strict front-end normalization and strict back-end validation;
- reject ambiguous or malformed messages and close the connection instead of
  attempting recovery;
- reject conflicting or invalid `Content-Length`, illegal transfer codings,
  malformed chunks/extensions, invalid whitespace, bare line endings, and
  HTTP/2 fields that cannot be represented safely in HTTP/1.1;
- handle `Expect`, interim responses, HEAD, early final responses, upgrades,
  and method bodies consistently at every hop;
- for HTTP/1.1 `CONNECT` on behalf of an untrusted TCP client, wait for a `2xx`
  before forwarding payload bytes or send `Connection: close`; a proxy server
  rejecting such a CONNECT must close without processing more requests (RFC
  9931). Do not optimistically send bytes for an Upgrade unless its protocol
  explicitly makes that safe;
- validate the target authority and routing decision on every request, not only
  the first request on a connection;
- avoid rewriting framing fields after validation; ensure dechunk/rechunk
  behavior cannot leave bytes behind;
- disable upstream reuse only as a temporary blast-radius reduction. It does
  not prevent request tunnelling, client-side desync, or every state attack;
- scan after each proxy, CDN, WAF, server, or routing change. Do not treat a WAF
  signature as equivalent to protocol-level request separation.

## Research map

James Kettle's main sequence should be read chronologically because each paper
adds a different attack surface:

1. [HTTP Desync Attacks: Request Smuggling Reborn (2019)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
   — modern CL.TE/TE.CL methodology, low-noise detection, and exploit chains.
2. [HTTP Desync Attacks: What Happened Next (2019)](https://portswigger.net/research/http-desync-attacks-what-happened-next)
   — operational gotchas, false positives, and updated detection.
3. [Breaking the Chains on HTTP Request Smuggler (2019)](https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler)
   — tool accuracy, safe-versus-risky confirmation, padding, and additional
   transfer-coding permutations.
4. [HTTP/2: The Sequel Is Always Worse (2021)](https://portswigger.net/research/http2)
   — H2.CL/H2.TE, HTTP/2-exclusive injection, request splitting, response-queue
   poisoning, and request tunnelling.
5. [Browser-Powered Desync Attacks (2022)](https://portswigger.net/research/browser-powered-desync-attacks)
   — CL.0/H2.0, client-side desync, pause-based attacks, and connection-state
   analysis.
6. [HTTP/3 Connection Contamination (2022)](https://portswigger.net/research/http-3-connection-contamination)
   — adjacent first-request-routing and connection-coalescing risk.
7. [Making HTTP Header Injection Critical via Response Queue Poisoning (2022)](https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning)
   — converting request/response header injection into desync impact.
8. [HTTP/1.1 Must Die: The Desync Endgame (2025)](https://portswigger.net/research/http1-must-die)
   — parser-discrepancy-first detection, V-H/H-V analysis, exploitable 0.CL,
   double desync, and `Expect`-based attacks.
9. [How to distinguish HTTP pipelining from request smuggling (2025)](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling)
   — current confirmation rules and the connection-locked exceptions.
10. [Introducing HTTP Anomaly Rank (2025)](https://portswigger.net/research/introducing-http-anomaly-rank)
    — scalable response-outlier ranking for high-volume differential probes.

The following work closes important non-Kettle coverage gaps:

- [TE.0 request smuggling (2024)](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)
- [Funky chunks: TERM.EXT and EXT.TERM (2025)](https://w4ke.info/2025/06/18/funky-chunks.html)
- [The Single-Packet Shovel: desync-powered request tunnelling (2025)](https://assured.se/posts/the-single-packet-shovel-desync-powered-request-tunnelling)
- [H2C smuggling](https://bishopfox.com/blog/h2c-smuggling-request)
- [Making desync attacks easy with TRACE (2024)](https://portswigger.net/research/trace-desync-attack)
- [Cloudflare Pingora request-smuggling postmortem (2025)](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora/)
- [Official 0.CL lab walkthrough (2026)](https://portswigger.net/blog/http-1-1-must-die-conquering-the-0-cl-challenge)

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [HTTP/2 Downgrading](http-attacks-http-2-downgrading.md) — severity hint: medium
- [Request Smuggling & HTTP Desync](http-attacks-request-smuggling-and-http-desync.md) — severity hint: high
<!-- END GENERATED TOPIC REFERENCES -->

## Sources

- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9931: Optimistic HTTP/1.1 Protocol Transitions](https://www.rfc-editor.org/rfc/rfc9931.html)
- [PortSwigger HTTP Request Smuggling Research index](https://portswigger.net/research/request-smuggling)
- [PortSwigger Advanced Request Smuggling](https://portswigger.net/web-security/request-smuggling/advanced)
