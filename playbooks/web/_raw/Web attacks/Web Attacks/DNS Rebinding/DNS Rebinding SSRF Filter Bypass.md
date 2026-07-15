# DNS Rebinding: SSRF Filter Bypass

# **Identifying the Vulnerability**

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

- Application resolves the domain name in the `index()` function twice
    - [socket.gethostbyname](https://docs.python.org/3/library/socket.html#socket.gethostbyname)
    - [requests.get](https://requests.readthedocs.io/en/latest/user/quickstart/)

# Methodology

- *We need to provide the web application with a domain under our control so that we can change its DNS configuration; for this section, suppose we own the domain `attacker.htb` and can change its DNS configuration. We will configure the DNS server to resolve `attacker.htb` to any IP address that is not blacklisted, such as `1.1.1.1`, and assign it a very low TTL.*
- *When we provide the web application with the URL `http://attacker.htb/flag`, it will resolve the domain name to `1.1.1.1` and verifies that it is not an internal IP address; since the function assigned to `global_check` evaluates to `True`, `global_check` becomes `True`. The `if` statement has both conditions evaluating to `True`, therefore allowing us access to the [render_template](https://flask.palletsprojects.com/en/2.0.x/quickstart/#rendering-templates) function.*
- *Subsequently, we will `rebind` the DNS configuration for `attacker.htb` to resolve to `127.0.0.1` instead of `1.1.1.1`. When attempting to get the flag in the `flag` function, and because of the low TTL assigned to `attacker.htb`, the web application will resolve `attacker.htb` again.*
- *At last, due to the DNS rebinding, the second DNS resolution will resolve the domain name `attacker.htb` to `127.0.0.1` such that the web application accesses the URL `http://127.0.0.1/flag` and fetches the flag for us.*

# **Debugging the Application Locally**

- First, we will add the domain `ourdomain.htb` to `/etc/hosts` and make it resolve to `1.1.1.1`

```python
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

1.1.1.1 ourdomain.htb
```

- After the initial resolution of the domain by `socket.getbyhostname`, we will set a breakpoint before `requests.get` performs a second resolution
- Change the entry to point to localhost

```python
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

127.0.0.1 ourdomain.htb
```

# Exploitation

- We can use https://lock.cmpxchg8b.com/rebinder.html
- DNS resolves randomly to the two IP’s
- Might require multiple attempts
- A cleaner way is to use our own domain https://github.com/mogwailabs/DNSrebinder
    - Configure an `NS`  DNS entry for our domain to point ot the IP of our machine

# **Exploiting Internal Webapps**

- https://lock.cmpxchg8b.com/rebinder.html only works for apps with internet access
- Host a personalized rouge DNS server utilizing tools like [DNSrebinder](https://github.com/mogwailabs/DNSrebinder) or [FakeDns](https://github.com/Crypt0s/FakeDns)
- Simultaneously, the DNS IP configuration of the targeted web application must be adjusted, rerouting it to the IP address of the our rogue DNS server
- Sometimes we can comrpomise assets like Webmin, Pihole etc. and reroute the traffic

```python
sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counter 1 --tcp --udp

Starting nameserver...
UDP server loop running in thread: Thread-1
TCP server loop running in thread: Thread-2
```