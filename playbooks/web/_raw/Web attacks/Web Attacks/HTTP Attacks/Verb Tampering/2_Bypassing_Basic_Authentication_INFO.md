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