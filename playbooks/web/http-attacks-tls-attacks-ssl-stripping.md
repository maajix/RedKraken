---
technique: "SSL Stripping"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/SSL Stripping.md"
source_sha256: "82231d37464755d31eca840fe2dd1ba73b6f1f1020e5e34390616b1490dfbd6c"
curator_version: 2
review_status: imported-unreviewed
---

# SSL Stripping

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: sudo apt install dsniff`
- `python: sudo arpspoof -i docker0 172.17.0.5`
- `python: $ arp`
- `python: docker run -it --privileged --net=host bettercap/bettercap --version`
- `python: docker run -it  bettercap/bettercap`
- `python: 172.17.0.0/16 > 172.17.0.2  » set arp.spoof.targets 172.17.0.4`
- `bash: $arp`
- `HTTP/2 200 OK`
- `HTTP/2 200 OK`

## Playbook (operator notes)

# SSL Stripping

### **ARP Spoofing**

- **ARP role:** Maps IP addresses to MAC addresses in local networks.
- **Normal process:**
    - Host broadcasts *“Who has IP X?”* (ARP request).
    - Target replies with its MAC address (ARP response).
    - Pair is cached locally for future use.
- **ARP spoofing/poisoning:**
    - Attacker sends forged ARP responses to impersonate another host.
    - Victim caches attacker’s MAC for the target’s IP.
    - Victim traffic meant for target is redirected to attacker.
- **Impact:** Attacker gains **Man-in-the-Middle (MitM)** position.
- **Detection:** Difficult, since no infrastructure changes occur.
- **Tooling:** Can be performed with `arpspoof` (dsniff package).

```python
sudo apt install dsniff
```

The program needs to be run as root. We have to specify the network interface and the IP address we want to impersonate. Let's assume we want to fool the docker container at `172.17.0.2` into thinking that we (running at `172.17.0.1`) are the target of `172.17.0.5`. We can spoof the ARP response by running:

```python
sudo arpspoof -i docker0 172.17.0.5
```

With this command, we periodically broadcast ARP responses saying that we are `172.17.0.5`. If the victim docker container now tries to contact the target of `172.17.0.5`, we successfully spoof the ARP request and fool the victim into thinking we are the target. We can verify this by showing the ARP cache on the 
victim. This can be done using the `arp` command:

```python
$ arp
Address                  HWtype  HWaddress           Flags Mask            Iface
172.17.0.1               ether   02:42:d4:13:6f:40   C                     eth0
172.17.0.5               ether   02:42:d4:13:6f:40   C                     eth0
```

Another tool:

```python
docker run -it --privileged --net=host bettercap/bettercap --version
bettercap v2.32.0 (built for linux amd64 with go1.16.4)
```

```python
docker run -it  bettercap/bettercap
bettercap v2.32.0 (built for linux amd64 with go1.16.4) [type 'help' for a list of commands]   
172.17.0.0/16 > 172.17.0.2  »
```

This time our target is running at `172.17.0.4`. Bettercap excludes internal IP addresses by default, so we need to set an extra option. We can do that and start the ARP spoofer like so:

```python
172.17.0.0/16 > 172.17.0.2  » set arp.spoof.targets 172.17.0.4
172.17.0.0/16 > 172.17.0.2  » set arp.spoof.internal true
172.17.0.0/16 > 172.17.0.2  » arp.spoof on
172.17.0.0/16 > 172.17.0.2  » [13:23:19] [sys.log] [war] arp.spoof arp spoofer started targeting 65534 possible network neighbours of 1 targets.
```

The output tells us that bettercap now spoofs all IP addresses in the target network of 172.17.0.0/16. A quick look at the traffic in Wireshark confirms this. We can see that bettercap sends spoofed ARP responses to the victim for all IP addresses in the target range. This is done over and over again to find the correct timing to poison the victim's ARP cache:

Lastly, let's look at the effect it has on our victim. Before we started the ARP spoofing attack, our victim's ARP cache looked like this:

```bash
$arp
Address     HWtype  HWaddress           Flags Mask   Iface
172.17.0.1  ether   02:42:0e:65:ef:ce   C            eth0
```

We can see that the MAC address corresponding to 172.17.0.1 has changed and now points to our attacker machine at 172.17.0.2, thus we have successfully poisoned the victim's ARP cache. Furthermore, after stopping the attack in bettercap with arp.spoof off, bettercap automatically restores the victim's poisoned ARP cache to the previous state such that no further clean-up is required:

---

### **SSL Stripping Attack**

- **SSL stripping attack:**
    - Conducted after gaining a MitM position (e.g., via ARP spoofing).
    - Forces victim to use **HTTP instead of HTTPS**, exposing data in plaintext.
- **Problem for attacker:**
    - Most web servers auto-redirect HTTP → HTTPS.
    - Without intervention, attacker cannot read encrypted TLS traffic.
- **Attacker’s trick:**
    - Intercept redirect to HTTPS.
    - Modify response so victim stays on HTTP.
    - Attacker still connects to target via HTTPS, maintaining MitM visibility.
        
        
        
- **Impact:** Victim unknowingly sends sensitive data (e.g., credentials) over unencrypted HTTP.
- **Attack setup:**
    - Victim → HTTP → Attacker
    - Attacker → HTTPS → Web server
- **Process:**
    - Victim’s HTTP request forwarded by attacker.
    - Server replies with HTTPS redirect.
    - Attacker suppresses redirect, instead establishes HTTPS with server.
    - Attacker relays data to victim over HTTP.
- **Result:**
    - Web server sees a secure TLS connection (attacker–server).
    - Victim only sees insecure HTTP (victim–attacker).
    - Attacker gains full access to sensitive data (credentials, payment info, etc.).
- Prevention
    
    The HTTP Header `Strict-Transport-Security` (HSTS) can be 
    used to prevent SSL Stripping attacks. This header tells the browser 
    that the target site should only be accessed through HTTPS. Any attempt 
    to access the site via HTTP is rejected by the browser or automatically 
    converted to HTTPS requests. This prevents SSL Stripping attacks for all
     websites that have been visited at least once in the past. If the HSTS 
    header was set, the browser prevents all HTTP communication with the web
     server such that there is no way for the MitM attacker to perform an 
    attack.
    
    **Note:** HSTS does not prevent attacks when 
    visiting a site for the first time. This initial connection can still be
     sent via insecure HTTP, leaving the door open for an SSL Stripping 
    attack.
    
    The HSTS header is set to a value in seconds. This is the time the 
    browser should store that the site can only be accessed via HTTPS. For 
    instance, when accessing `https://www.google.com`, we receive the following response:
    
    The HSTS header is set to a value in seconds. This is the time the 
    browser should store that the site can only be accessed via HTTPS. For 
    instance, when accessing `https://www.google.com`, we receive the following response:
    
    ```
    HTTP/2 200 OK
    Date: Thu, 29 Dec 2022 15:15:38 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=UTF-8
    Strict-Transport-Security: max-age=31536000
    
    <SNIP>
    ```
    
    We can see the HSTS header in the response. It is set to `31536000`
     seconds, which is exactly one year. So, after accessing the website for
     the first time, all HTTP access is prevented for an entire year.
    
    Additionally, websites can protect subdomains with the `includeSubDomains`
     directive. This tells the web browser to automatically connect to all 
    subdomains using HTTPS, even if they have not been visited before. An 
    example could look like this:
    
    ```
    HTTP/2 200 OK
    Date: Thu, 29 Dec 2022 15:15:38 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=UTF-8
    Strict-Transport-Security: max-age=31536000; includeSubDomains
    
    <SNIP>
    ```

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/SSL Stripping.md`
