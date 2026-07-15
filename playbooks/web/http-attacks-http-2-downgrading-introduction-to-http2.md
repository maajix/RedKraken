---
technique: "Introduction to HTTP2"
family: "http-protocol"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Introduction to HTTP2.md"
source_sha256: "0d6f3f4a94f052701a42180260ef21c5544bed4e593593817bc1a655a9a0f0e1"
curator_version: 2
review_status: imported-unreviewed
---

# Introduction to HTTP2

> Family: **http-protocol** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: GET /index.php HTTP/1.1`
- `:method GET`

## Playbook (operator notes)

# Introduction to HTTP2

## **What is HTTP/2?**

- Improvement to HTTP traffic with backwards compatibillity
- Data is formatted differently during transmission to allow fo performance improvements, methods, header etc still exists
- No difference in web proxy like Burp since HTTP/2 (same data)
- HTTP/1.1 string based, meaning req and res are sent as strings vs HTTP/2 is binary
- HTTP/2 allows server to push content to client without prior requests
    - Helpful for static resources, scripts, img

```python
GET /index.php HTTP/1.1
Host: http2.htb
```

In HTTP/2, the same request is represented using so-called `pseudo-headers`:

```
:method GET
:path /index.php
:authority http2.htb
:scheme http
```

The following pseudo-headers are defined in an HTTP/2 request. Have a look at section 8.3.1 of the RFC [here](https://datatracker.ietf.org/doc/html/rfc9113#name-request-pseudo-header-field) for more details:

- `:method`: the HTTP method
- `:scheme`: the protocol scheme (typically `http` or `https`)
- `:authority`: similar to the HTTP `Host` header
- `:path`: the requested path including the query string

Burp displays requests in the HTTP/1.1 format. However, in Burp Repeater we can see the HTTP/2 pseudo-headers in the Burp Inspector:

Another change that is important regarding security, particularly regarding request smuggling, is that the `chunked` encoding is no longer supported in HTTP/2. Additionally, since HTTP/2 transmits the request body in a binary format consisting of data frames, there is no explicit length field required to determine the length of the request body. The data frames contain a built-in length field that any system can use to calculate the request body's length. Thus, request smuggling attacks are almost impossible if HTTP/2 is used correctly in a deployment setting.

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Introduction to HTTP2.md`
