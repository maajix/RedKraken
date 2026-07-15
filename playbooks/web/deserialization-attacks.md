---
technique: "Deserialization Attacks"
family: "deserialization"
severity_hint: "critical"
tags: ["Deserialization", "PHP", "Python", "Remote Code Execution", "Account Takeover", "Session Tokens", "HTTP", "Authentication", "File Upload"]
source: "_raw/Web attacks/Web Attacks/Deserialization Attacks.md"
source_sha256: "dcf065d75c4d410389077b1cc6cfc0361cd796ab3ae9a4e97917f1e13dd41a7f"
curator_version: 2
review_status: imported-unreviewed
---

# Deserialization Attacks

> Family: **deserialization** · Severity hint: **critical** · Tags: Deserialization, PHP, Python, Remote Code Execution, Account Takeover, Session Tokens, HTTP, Authentication, File Upload
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: sudo tcpdump -i tun0`

## Playbook (operator notes)

# Deserialization Attacks

https://net-square.com/yaml-deserialization-attack-in-python.html

https://davidhamann.de/2020/04/05/exploiting-python-pickle/

https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/

https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf

---

deserialize.pdf

---

Introduction

**Exploiting PHP Deserialization**

**Exploiting Python Deserialization**

---

**Defending against Deserialization Attacks**

**Tools of the Trade (PHP Deserialization)**%2027e2c37daa298001b348f12e9ed97ed6.md)

**Tools of the Trade (Python Deserialization)**%2027e2c37daa29801e9fe8ccd24256e141.md)

---

```python
sudo tcpdump -i tun0

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:28:15.131656 IP view-localhost > view-localhost: ICMP echo request, id 63693, seq 1, length 64
15:28:15.131668 IP view-localhost > view-localhost: ICMP echo reply, id 63693, seq 1, length 64
15:28:16.135472 IP view-localhost > view-localhost: ICMP echo request, id 63693, seq 2, length 64
...
```

## Source
Original note: `_raw/Web attacks/Web Attacks/Deserialization Attacks.md`
