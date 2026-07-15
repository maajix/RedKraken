# Rate-Limit Bypass

Status: Erledigt
Tags: Rate-Limit (../Tags/Rate-Limit%2027f2c37daa29808f8d12f04d7be6248b.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md)
Tags 2: HTTP

# Rate Limit Bypass Techniques

- Rate Limit Bypass using Header
    - Try changing the user-agent, cookies etc.
    - Try using Headers like:
        
        ```haskell
        X-Forwarded: 127.0.0.1
        X-Forwarded-By: 127.0.0.1
        X-Forwarded-For: 127.0.0.1
        X-Forwarded-For-Original: 127.0.0.1
        X-Forwarder-For: 127.0.0.1
        X-Forward-For: 127.0.0.1
        Forwarded-For: 127.0.0.1
        Forwarded-For-Ip: 127.0.0.1
        X-Custom-IP-Authorization: 127.0.0.1
        X-Originating-IP: 127.0.0.1
        X-Remote-IP: 127.0.0.1
        X-Remote-Addr: 127.0.0.1
        
        -- Double X-Forwarded-For header example --
        X-Forwarded-For:
        X-Forwarded-For: 127.0.0.1
        ```
        
- Rate Limit Bypass using Special Characters
    - Adding `%00` at the end of the Email can sometimes Bypass Rate Limit
    - Try adding a Space Character after a Email (Not Encoded)
    - Some Common Characters that help bypassing Rate Limit :
        - `%0d , %2e , %09 , %20 , %0, %00, %0d%0a, %0a, %0C`
    - Adding a `/` at the end of API endpoint can also Bypass Rate Limits
        - `domain.com/v1/login` -> `domain.com/v1/login/`
- Leveraging API Gateway Behavior
    
    Some API gateways are configured to apply rate limiting based on the combination of endpoint and parameters. By varying the parameter values or adding non-significant parameters to the request, it's possible to circumvent the gateway's rate-limiting logic, making each request appear unique. For exmple `/resetpwd?someparam=1`.
    
- Logging into Your Account Before Each Attempt
    
    Logging into an account before each attempt, or every set of attempts, might reset the rate limit counter. This is especially useful when testing login functionalities. Utilizing a Pitchfork attack in tools like Burp Suite, to rotate credentials every few attempts and ensuring follow redirects are marked, can effectively restart rate limit counters.
    
- Play with requests
    - Change the request body from its current type e.g JSON ↔  XML
    - Change request methods PUT ↔ POST ↔ GET

---

[Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)

[Rate-Limit Bypass](https://kathan19.gitbook.io/howtohunt/rate-limit/ratelimitbypass)