---
technique: "2_Bypassing_Basic_Authentication_INFO"
family: "http-protocol"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/2_Bypassing_Basic_Authentication_INFO.md"
source_sha256: "4c5672236f46468f0422d556fcb333f07aa2c86e697789856af06fea861110d1"
curator_version: 2
review_status: imported-unreviewed
---

# 2_Bypassing_Basic_Authentication_INFO

> Family: **http-protocol** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: curl.

## Quick index — payloads & commands in this note
- `bash: $ curl -i -X OPTIONS http://SERVER_IP:PORT/`

## Playbook (operator notes)

# 2_Bypassing_Basic_Authentication_INFO

- While many automated vulnerability scanning tools can consistently identify HTTP Verb Tampering vulnerabilities caused by insecure server configurations, they usually miss identifying HTTP Tampering vulnerabilities caused by insecure coding

## Exploit

- Intercept the request in Burp Suite
- Identify the HTTP method
- Change the method around and see if the website behaves strange
- To see which HTTP methods are allowed use the following command

```bash
$ curl -i -X OPTIONS http://SERVER_IP:PORT/
HTTP/1.1 200 OK
Date:
Server: Apache/2.4.41 (Ubuntu)Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/2_Bypassing_Basic_Authentication_INFO.md`
