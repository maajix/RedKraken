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

![image.png](Introduction%20to%20HTTP2/image.png)

Another change that is important regarding security, particularly regarding request smuggling, is that the `chunked` encoding is no longer supported in HTTP/2. Additionally, since HTTP/2 transmits the request body in a binary format consisting of data frames, there is no explicit length field required to determine the length of the request body. The data frames contain a built-in length field that any system can use to calculate the request body's length. Thus, request smuggling attacks are almost impossible if HTTP/2 is used correctly in a deployment setting.