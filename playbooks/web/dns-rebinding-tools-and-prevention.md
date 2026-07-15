---
technique: "Tools & Prevention"
family: "ssrf-xxe-file"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/DNS Rebinding/Tools & Prevention.md"
source_sha256: "48531549c3d547aa71d1d817865623b98fc41d4d7c6033e93f2f649c0fc295b9"
curator_version: 2
review_status: imported-unreviewed
---

# Tools & Prevention

> Family: **ssrf-xxe-file** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: python3.

## Quick index — payloads & commands in this note
- `python: sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counte`
- `bash: git clone https://github.com/nccgroup/singularity`

## Playbook (operator notes)

# Tools & Prevention

# **DNS Rebinding Tools**

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

- Configure singularity as our NS for our domain

https://github.com/nccgroup/singularity/wiki/Setup-and-Installation

---

# **Prevention**

- Details
    
    ### **SSRF Filter Bypasses**
    
    As we have discussed, preventing access to the internal network via SSRF filters is a challenging task. We must consider how different protocols, such as DNS and HTTP, interplay and what options an attacker has to make our application access the internal network. Generally, there are a few best practices we can apply to reduce the risk:
    
    1. Resolve the domain name passed to the application before checking it; this ensures that we are working on an IP address in the format we expect, and we do not have to worry about domain names such as `localtest.me`, `localhost` or IP addresses in an unexpected format (such as hex or octal representations).
    2. If possible, check the resolved IP address against a whitelist of allowed IP addresses. If this is impossible, block the entire private IP address range, i.e., `10.0.0.0/8`, `172.16.0.0./12`, and `192.168.0.0/16`. Additionally, block all IP addresses that might resolve to the local machine, which include `127.0.0.0/8` and `0.0.0.0/8`.
    3. Consider redirects. If the application follows redirects, consider how the filter can be bypassed using HTTP or HTML redirects and implement application-dependent mitigations accordingly.
    4. Most importantly: Implement firewall rules that prevent outgoing access from the system the vulnerable application runs on to the internal network. This prevents any access even if filters get bypassed.
    
    Preventing SSRF filter bypasses via DNS rebinding can be achieved by not resolving the domain name twice. After resolving it in the SSRF filter, we need to fix the resolved IP address and reuse it when the application makes the actual request; the implementation of how to achieve this is application dependent.
    
    ### **DNS Rebinding**
    
    The danger of Same-Origin policy bypasses via DNS rebinding is that this technique enables attackers to access applications running in the victim's local network, thus circumventing security controls such as firewalls or NAT. System administrators often assume that the local network is trusted and that no additional authentication is required when accessing an application. For instance, if there is a printer on the local network, everyone who can connect to the printer can typically print without any authentication. However, as we learned, DNS rebinding breaches these faulty assumptions.
    
    Because DNS rebinding vulnerabilities are not caused by a specific flaw in an application, we need to ensure the following best practices when designing our internal network:
    
    1. Use authentication on all services in the internal network. DNS rebinding can only be used to access internal applications with the cookies of the corresponding domain name. If an attacker does not know credentials to the internal application to log in themselves, only unauthenticated access can be achieved. Thus, it is vital to protect sensitive information or functionality using authentication, even if it is only exposed within the local network.
    2. Use TLS on all external and internal services. If an attacker uses DNS rebinding to access an internal service over TLS, there will be a certificate mismatch as the access uses an incorrect domain name. For more details about HTTPs and TLS attacks, check out the [HTTPs/TLS Attacks](https://academy.hackthebox.com/module/details/184) module.
    
    Additionally, there are a few hardening measures we can implement to prevent DNS rebinding attacks:
    
    1. Refuse DNS lookups of internal IP addresses. Suppose the DNS server responds to any DNS request containing a domain name that resolves to an internal IP address with an `NXDOMAIN` response (i.e., a response indicating that the domain name does not exist). In that case, it becomes impossible to conduct DNS rebinding since internal IP addresses are not resolved.
    2. Validate the HTTP `Host` header of incoming HTTP requests. Due to the nature of DNS rebinding, the resulting access to the internal network uses an incorrect domain name and, thus, an incorrect `Host` header. If the targeted application checks the `Host` header, it receives an unexpected value and should reject the request. For more details on the `Host` header and its attacks, check out the [Abusing HTTP Misconfigurations](https://academy.hackthebox.com/module/details/189) module.

## Source
Original note: `_raw/Web attacks/Web Attacks/DNS Rebinding/Tools & Prevention.md`
