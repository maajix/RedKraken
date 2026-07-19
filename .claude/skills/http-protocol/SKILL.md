---
name: http-protocol-attacks
description: Triage and exploit HTTP/transport-layer flaws — request smuggling & HTTP desync, host-header attacks, CRLF injection & response splitting, web cache poisoning, HTTP verb tampering, HTTP/2 downgrade, parameter pollution, status-code/403 bypass, and TLS attacks. Use when probing proxies/CDNs, caches, headers, or routing.
---

# HTTP / Protocol Family

Covers: **request smuggling / HTTP desync**, **host-header attacks**, **CRLF injection & response splitting**, **cache poisoning/deception**, **verb tampering**, **HTTP/2 downgrade**, **parameter pollution**, **status-code / 403 bypass**, **TLS attacks**. Route through `playbooks/_catalog.md`; read `playbooks/http-desync/README.md` or `playbooks/web-cache/README.md` first when their signals match, then consult sibling imported references only for additional depth. Obey `scope-guard` + `tool-preflight`.

## Signals → technique

| Signal | Try |
|--------|-----|
| front-end proxy / CDN / load balancer | parser-discrepancy probes, classic and modern desync matrix, H2 downgrade |
| mutated real header behaves differently from matched controls | classify V-H/H-V parser discrepancy before choosing CL.0, 0.CL, or TE-based confirmation |
| `Expect: 100-continue`, interim/final response, or HEAD/body anomaly | Expect/early-response desync; isolate because response parsing and memory exposure are possible |
| hidden HTTP/2, HTTP/1.1 upstream, or forwarded h2c upgrade | H2.CL/H2.TE/H2.0, HTTP/2 injection/tunnelling, h2c smuggling |
| HTTP/1.1 CONNECT/Upgrade client sends payload before acceptance | RFC 9931 optimistic-transition smuggling; test the rejection path |
| apparent finding only with client connection reuse | rule out pipelining; then assess connection-locked smuggling, connection state, or CSD |
| app reflects/uses `Host` header (links, reset, cache key) | host-header injection, password-reset poisoning, cache poisoning |
| header/param reflected unencoded into response/headers | CRLF, response splitting |
| cacheable responses keyed loosely | web cache poisoning / deception |
| 403/401 on a path | verb tampering (GET↔POST↔PUT↔HEAD), status-code bypass tricks |
| duplicate params handled inconsistently | HTTP parameter pollution |

## Approach

1. **Request smuggling.** Classify parser disagreement with matched controls, then confirm with independently issued tester-owned canaries and client connection reuse disabled by default. In addition to CL.TE/TE.CL, cover CL.0, 0.CL, TE.0, chunk-extension/body/trailer differentials, `Expect`, pause/early-response, H2 downgrade/tunnelling, optimistic transition, and connection-state discrepancies one at a time. Reuse the client connection only when deliberately triaging connection-locked smuggling, connection state, or CSD. Timing alone is only a lead. Cross-user traffic, response-queue poisoning, and cache impact are high blast radius and require explicit destructive authorization plus isolation.
2. **Host-header.** Inject `Host:`/`X-Forwarded-Host` → poisoned password-reset links, SSRF-ish routing, cache poisoning. Confirm reflection in body/headers/emails.
3. **CRLF / response splitting.** `%0d%0a` to inject headers (Set-Cookie, redirect) → session fixation, XSS via injected headers, cache poisoning.
4. **Cache poisoning.** Find unkeyed inputs (headers/params) that influence a cached response; poison and prove a second client receives it.
5. **Verb tampering / 403 bypass.** Swap methods, try `X-Original-URL`/`X-Rewrite-URL`, path-case/encoding/`;` tricks, trailing dot/slash.
6. **HTTP/2/3 downgrade, coalescing & TLS.** Trace every upstream protocol, test
   downgrade normalization and connection routing with tester-owned origins, and
   prefer HTTP/2+ upstream as the durable desync fix. For TLS use `openssl
   s_client`/`testssl.sh` — weak protocols/ciphers, Heartbleed, padding oracles
   (mostly reporting-grade unless directly exploitable).

## Evidence
Save the raw request/frames and the observed tester-owned canary effect. Smuggling and cache poisoning can hit real users: default to isolated, self-contained confirmation and stop.
