# Host-Header

[Collaborator Everywhere](https://portswigger.net/bappstore/2495f6fb364d48c3b6c984e226c02968)

[Handy Collaborator](https://portswigger.net/bappstore/dcf7c44cdc7b4698bba86d94c692fb7f)

### What is the HTTP Host header

- The HTTP Host header is a mandatory request header as of HTTP/1.1
- Specifies the domain name that the client wants to access
- In some cases, such as when the request has been forwarded by an intermediary system, the Host value may be altered before it reaches the intended back-end component

```python
GET /web-security HTTP/1.1
Host: portswigger.net
```

### What is the purpose of the HTTP Host header?

- Purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with
- If requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application
- Historically, this ambiguity didn't exist because each IP address would only host content for a single domain
- Nowadays, largely due to the ever-growing trend for cloud-based solutions and outsourcing much of the related architecture, it is common for multiple websites and applications to be accessible at the same IP address
- When multiple applications are accessible via the same IP address, this is most commonly a result of one of the following scenarios

### Virtual hosting

- This could be multiple websites with a single owner, but it is also possible for websites with different owners to be hosted on a single, shared platform
- This is less common than it used to be, but still occurs with some cloud-based SaaS solutions
- In either case, although each of these distinct websites will have a different domain name, they all share a common IP address with the server
- Websites hosted in this way on a single server are known as "virtual hosts"
- To a normal user accessing the website, a virtual host is often indistinguishable from a website being hosted on its own dedicated server

### Routing traffic via an intermediary

- When websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system
- This could be a simple load balancer or a reverse proxy server of some kind
- This setup is especially used in cases where clients access the website via a content delivery network (CDN)
- In this case, even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component
- This presents some of the same challenges as virtual hosting because the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request

### How does the HTTP Host header solve this problem?

- In both of these scenarios, the Host header is relied on to specify the intended recipient
- When a browser sends the request, the target URL will resolve to the IP address of a particular server
- When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly

### What is an HTTP Host header attack?

- Attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way
- If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior
- Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks
- Off-the-shelf web applications typically don't know what domain they are deployed on unless it is manually specified in a configuration file during setup
- When they need to know the current domain, for example, to generate an absolute URL included in an email, they may resort to retrieving the domain from the Host header

```html
<a href="https://_SERVER['HOST']/support">Contact support</a>
```

- The header value may also be used in a variety of interactions between different systems of the website's infrastructure
- As the Host header is in fact user controllable, this practice can lead to a number of issues
- If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably
    - Web cache poisoning
    - Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
    - Routing-based SSRF
    - Classic server-side vulnerabilities, such as SQL injection

# Identification

1. Check weather changing headers result in a reflected value in the response
2. When changing values, always make sure to check combinations and also change every **override** header to the attacker controlled one

# Check this while testing

1. Add two `HOST:` in Request.
2. Try adding additional override Headers [WAF Bypasses](../WAF%20Bypasses%20dc417f1faca948c08da7ed02bff6ceab.md)    
3. If you come across `/api.json` in any AEM instance during bug hunting, look for web cache poisoning via `Host: , X-Forwarded-Server , X-Forwarded-Host:`  or simply try `https://localhost/api.json HTTP/1.1`
4. Also try `Host: redacted.com.evil.com`
5. `Host: evil.com/redacted.com` [[https://hackerone.com/reports/317476](https://hackerone.com/reports/317476)]
6. `Host: example.com?.mavenlink.com`
7. `Host: javascript:alert(1);` Xss payload might result in debugging mode [[https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html](https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)]
    
    ```html
    Host: vulnerable-website.com:bad-stuff-here
    Host: my-website-vulnerable-website.com
    hacked-subdomain.vulnerable-website.com
    ```
    
8. Host Header to SQLi [[https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610](https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610)]
9. Bypass front-end server restrictions and access forbidden files / directories through `X-Rewrite-Url/X-original-url:` 
    1. `curl -i -s -k -X 'GET' -H 'Host: <site>' -H 'X-rewrite-url: admin/login' 'https://<site>/'`
10. Double Host Header
    
    ```python
    GET /example HTTP/1.1 
    Host: vulnerable-website.com 
    Host: bad-stuff-here
    ```
    

### Supply an absolute URL

- Although the request line typically specifies a relative path on the requested domain, many servers are also configured to understand requests for absolute URLs
- The ambiguity caused by supplying both an absolute URL and a Host header can also lead to discrepancies between different systems
- Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case
- Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL

```python
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

### Add line wrapping

- You can also uncover quirky behavior by indenting HTTP headers with a space character
- Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value
- Other servers will ignore the indented header altogether
- Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request
- The website may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them

```
GET /example HTTP/1.1
	Host: bad-stuff-here
Host: vulnerable-website.com
```

- If the front-end ignores the indented header, the request will be processed as an ordinary request for `vulnerable-website.com`
- Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates
- This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header

## SSRF via a malformed request line

- Custom proxies sometimes fail to validate the request line properly, which can allow you to supply unusual, malformed input with unfortunate results
- For example, a reverse proxy might take the path from the request line, prefix it with `http://backend-server`, and route the request to that upstream URL
- This works fine if the path starts with a `/` character, but what if starts with an `@` character instead
- The resulting upstream URL will be `http://backend-server@private-intranet/example`, which most HTTP libraries interpret as a request to access `private-intranet` with the username `backend-server`

```
GET @private-intranet/example HTTP/1.1
```

# Web Cache Poisoning

- Can be combined with [Cache Poisoning](../Cache%20Poisoning%2083ece7478d4c4a6295f345c3b64b216d.md)
- If the host header is keyed, try to find different override headers that are unkeyed

# **Fuzzing**

- If a website only allows access locally, try fuzzing the host header with internal IP’s
    - E.g `/admin/login` → `Host: FUZZ` → `192.168.X.X`

```elixir
for a in {1..255};do
    for b in {1..255};do
        echo "192.168.$a.$b" >> ips.txt
    done
done
```

```elixir
$ ffuf -u http://IP:PORT/admin.php -w ips.txt -H 'Host: FUZZ' -fs 752
```

---

[Host-Header](https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header)