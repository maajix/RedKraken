# Status Code Bypass

Status: Erledigt
Tags: 403 (../Tags/403%2027f2c37daa2980c7b62be7b31dee36cc.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md)
Tags 2: HTTP

[https://github.com/iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403)

[https://github.com/Dheerajmadhukar/4-ZERO-3](https://github.com/Dheerajmadhukar/4-ZERO-3)

[https://github.com/yunemse48/403bypasser](https://github.com/yunemse48/403bypasser)

[https://github.com/carlospolop/fuzzhttpbypass](https://github.com/carlospolop/fuzzhttpbypass)

[403 Bypasser](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122)

[Collaborator Everywhere](https://portswigger.net/bappstore/2495f6fb364d48c3b6c984e226c02968)

# 403 Bypass

- Directory Based
    
    ```haskell
    site.com/secret => 403
    site.com/secret/* => 200
    site.com/secret/./ => 200
    ```
    
- File Base
    
    ```haskell
    site.com/secret.txt => 403
    site.com/secret.txt/ => 200
    site.com/%2f/secret.txt/ => 200
    ```
    
- Protocol Base
    
    ```haskell
    https://site.com/secret => 403
    http://site.com/secret => 200
    ```
    
- Payloads
    
    ```haskell
    /
    /*
    /%2f/
    /./
    ./.
    /*/
    ```
    
- HTTP Verbs/Methods Fuzzing
    
    Try using **different verbs** to access the file: `GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH, INVENTED, HACK`
    
    - Check the response headers, maybe some information can be given. For example, a **200 response** to **HEAD** with `Content-Length: 55` means that the **HEAD verb can access the info**. But you still need to find a way to exfiltrate that info
    - Using a HTTP header like `X-HTTP-Method-Override: PUT` can overwrite the verb used
    - Use **`TRACE`** verb and if you are very lucky maybe in the response you can see also the **headers added by intermediate proxies** that might be useful
- HTTP Headers Fuzzing
    - **Change Host header** to some arbitrary value ([that worked here](https://medium.com/@sechunter/exploiting-admin-panel-like-a-boss-fc2dd2499d31))
    - Try to [**use other User Agents**](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/User-Agents/UserAgents.fuzz.txt) to access the resource
    - **Fuzz HTTP Headers**: Try using HTTP Proxy **Headers**, HTTP Authentication Basic and NTLM brute-force (with a few combinations only) and other techniques → [**fuzzhttpbypass**](https://github.com/carlospolop/fuzzhttpbypass)
        - `X-Originating-IP: 127.0.0.1`
        - `X-Forwarded-For: 127.0.0.1`
        - `X-Forwarded: 127.0.0.1`
        - `Forwarded-For: 127.0.0.1`
        - `X-Remote-IP: 127.0.0.1`
        - `X-Remote-Addr: 127.0.0.1`
        - `X-ProxyUser-Ip: 127.0.0.1`
        - `X-Original-URL: 127.0.0.1`
        - `Client-IP: 127.0.0.1`
        - `True-Client-IP: 127.0.0.1`
        - `Cluster-Client-IP: 127.0.0.1`
        - `X-ProxyUser-Ip: 127.0.0.1`
        - `Host: localhost`
    - If the **path is protected** you can try to bypass the path protection using these other headers:
        - `X-Original-URL: /admin/console`
        - `X-Rewrite-URL: /admin/console`
    - If the page is **behind a proxy**, try abusing [Request Smuggling & HTTP Desync](HTTP%20Attacks/Request%20Smuggling%20&%20HTTP%20Desync%20d2b55b032f3f45fd9d4afdbdfd3b0087.md) **or** [**hop-by-hop headers](https://book.hacktricks.xyz/pentesting-web/abusing-hop-by-hop-headers).**
    - Fuzz [**special HTTP headers**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers) looking for different response
        - **Fuzz special HTTP headers** while fuzzing **HTTP Methods**
    - **Remove the Host header** and maybe you will be able to bypass the protection
- Path Fuzzing
    - If the path is blocked try fuzzing [Wordlists](https://app.notion.com/p/Wordlists-96a8e3defd6c413f84b47fc4c214c251?pvs=21)
- Parameter Manipulation
    - Change **param value**: From **`id=123` → `id=124`**
    - Add additional parameters to the URL: `?**id=124` → `id=124&isAdmin=true`**
    - Remove the parameters
    - Re-order parameters
    - Use special characters
    - Perform boundary testing in the parameters — provide values like *-234* or *0* or *99999999* (just some example values)
- Protocol version
    
    If using HTTP/1.1 **try to use 1.0** or even test if it **supports 2.0**
    
- Other Bypasses
    - Get the **IP** or **CNAME** of the domain and try **contacting it directly**
    - Try to **stress the server ([**Race Conditions & Timing Attacks**](Race%20Conditions%20&%20Timing%20Attacks%2074b7da60c5f64298ab13a7333db611bb.md))** by sending common GET requests ([It worked for this guy with Facebook](https://medium.com/@amineaboud/story-of-a-weird-vulnerability-i-found-on-facebook-fc0875eb5125))
    - Go to [**https://archive.org/web/**](https://archive.org/web/) and check if in the past that file was **worldwide accessible**
- Assetnote nowafpls burp
    
    https://github.com/assetnote/nowafpls?tab=readme-ov-file#installing-nowafpls
    

---

[Status_Code_Bypass Tips](https://kathan19.gitbook.io/howtohunt/status-code-bypass/status_code_bypass)

[403 Bypass](https://kathan19.gitbook.io/howtohunt/status-code-bypass/403bypass)

[403 & 401 Bypasses](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)