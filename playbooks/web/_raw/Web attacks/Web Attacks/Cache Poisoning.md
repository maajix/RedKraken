# Cache Poisoning

Status: Erledigt
Tags: Cache Poisoning (../Tags/Cache%20Poisoning%2027f2c37daa2980fdb595da7e57073620.md), 403 (../Tags/403%2027f2c37daa2980c7b62be7b31dee36cc.md), XSS (../Tags/XSS%2027f2c37daa29805dadb2ff82553491b9.md), DoS (../Tags/DoS%2027f2c37daa298038bf49ddd08fc8ea15.md), JavaScript (JS) (../Tags/JavaScript%20(JS)%2027f2c37daa29809aac00f50467f7187c.md), HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md)
Tags 2: HTTP

[https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)

[Web Cache Poisoning](https://app.notion.com/p/Web-Cache-Poisoning-364023aa8fcd439fa743ffaea683998b?pvs=21) 

# **Web cache poisoning vs Web cache deception**

- In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users
- In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache

# Bypass Cache Hits for testing

- If many users use the website and we only get the cached site try to bypass the cache
- Try to set the `Cache-Control: no-cache` header
- We could also try the deprecated `Pragma: no-cache` header
- We need to wait until the cache copy expires until our requests are visible

# Discovery: Check HTTP headers

[WAF Bypasses](WAF%20Bypasses%20dc417f1faca948c08da7ed02bff6ceab.md) 

[Special HTTP headers](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers#cache-headers)

- Pay attention to different **Server Cache Headers**:
    - **`X-Cache`** in the response may have the value **`miss`** when the request wasn't cached and the value **`hit`** when it is cached Similar behavior in the header **`Cf-Cache-Status`**
    - **`Cache-Control`** indicates if a resource is being cached and when will be the next time the resource will be cached again: `Cache-Control: public, max-age=1800`
    - **`Vary`** is often used in the response to **indicate additional headers** that are treated as **part of the cache key** even if they are normally unkeyed
    - **`Age`** defines the times in seconds the object has been in the proxy cache
    - **`Server-Timing: cdn-cache; desc=HIT`** also indicates that a resource was cached

# Discovery: Caching 400 code

1. If you are thinking that the response is being stored in a cache, you could try to send requests with a bad header, which should be responded to with a status code 400
2. Then try to access the request normally and if the response is a 400 status code → you know it's vulnerable (and you could even perform a DoS)
    1. A badly configured header could be just `\:` as a header
    2. Note that sometimes these kinds of status codes aren't cached so this test will be useless

# Discovery: Identify and evaluate unkeyed inputs

1. Use [**Param Miner**](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to **brute-force parameters and headers** that may be **changing the response of the page**
    1. For example, a page may be using the header `X-Forwarded-For` to indicate the client to load the script from there
2. With the parameter/header identified check how it is being **sanitized** and **where** is it **getting reflected** or affecting the response from the header
    1. Can you abuse it anyway (perform an XSS or load a JS code controlled by you? perform a DoS?...)
3. Next try to get the page cached
    1. Depending on the resource you are trying to get in the cache this could take some time, you might need to be trying for several seconds
    2. Pay attention for **Server Cache Headers**
    3. When caching a request, be **careful with the headers you use** because some of them could be **used unexpectedly** as **keyed** and the **victim will need to use that same header**
        
        <aside>
        ⚠️ Always **test** a Cache Poisoning with **different browsers** to check if it's working
        
        </aside>
        
        <aside>
        ⚠️ Always use `Cache Busters` (*set the keyed values to a random one*) in real world application testing to make sure that no other user requests this resource
        
        </aside>
        

# Check for fat GET parameters

- Check with param miner for fat GET parameters
- If we can find any the web server is misconfigured and we might be able to poison a keyed parameter through the fat GET
    
    ```elixir
    GET /index.php?language=en HTTP/1.1
    Host: fatget.wcp.htb
    Content-Length: 11
    
    language=de
    ```
    
    <aside>
    ℹ️ **Note:** fat GET requests are typically a misconfiguration in the web server software, not in the web application itself.
    
    </aside>
    

# **Parameter Cloaking**

[Bottle: Python Web Framework — Bottle 0.13-dev documentation](https://bottlepy.org/docs/dev/)

- Same idea as in fat GET requests to create a discrepancy in a way that the web cache uses a different parameter for the cache key than the web server uses to serve the response
- Real world example
    - Bottle (python framework) allows a semicolon for separation between different URL parameters `/test?a=1;b=2`
    - Since Bottle treats the semicolon as a separation character, it sees two GET parameters: `a` with a value of `1` and `b` with a value of `2`
    - The web cache on the other hand only sees one GET parameter `a` with a value of `1;b=2`
    
    ```elixir
    GET /?language=en&a=b;language=de HTTP/1.1
    Host: cloak.wcp.htb
    ```
    
    <aside>
    ℹ️ **Note:** To poison the cache with parameter cloaking we need to "hide" the cloaked parameter from the cache key by appending it to an unkeyed parameter.
    
    </aside>
    
    ```
    GET /?language=de&a=b;ref<XSS> HTTP/1.1
    Host: cloak.wcp.htb
    ```
    

# Mitigation

- Prevention
    
    Due to their complex nature, preventing web cache poisoning vulnerabilities is no easy task. In some settings, the backend developers might be unaware that there is a web cache in front of the web server in the actual deployment setting. Furthermore, the administrators configuring the web cache and the cache key might be different people than the backend developers. This can introduce hidden unkeyed parameters that the web application uses to alter the response, leading to potential web cache poisoning vectors.
    
    Configuring the web cache properly depends highly on the web server and web application it is combined with. Thus, we need to ensure the following things:
    
    - Do not use the default web cache configuration. Configure the web cache properly according to your web application's needs
    - Ensure that the web server does not support fat GET requests
    - Ensure that every request parameter that influences the response in any way is keyed
    - Keep the web cache and web server up to date to prevent bugs and other vulnerabilities which can potentially result in discrepancies in request parsing leading to parameter cloaking
    - Ensure that all client-side vulnerabilities such as XSS are patched even if they are not exploitable in a classical sense (for instance via reflected XSS). This may be the case if a custom header is required. Web cache poisoning can make these vulnerabilities exploitable, so it is important to patch them
    
    Furthermore, administrators should assess if caching is required. Of course, web caches are important for many circumstances, however, there might be others where it is not required and only increases deployment complexity. Another less drastic approach might be limiting caching to only static resources such as stylesheets and scripts. This eliminates web cache poisoning entirely. Though it can create new issues if an attacker can trick the web cache into caching a resource that is not actually static.
    

---

[Cache Poisoning and Cache Deception](https://book.hacktricks.xyz/pentesting-web/cache-deception)