---
technique: "The Heartbleed Bug"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/The Heartbleed Bug.md"
source_sha256: "db04a1228111a66ecedfff468bfea0a9c9106e0387e32e7e6e81c6d719854cd7"
curator_version: 2
review_status: imported-unreviewed
---

# The Heartbleed Bug

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: java -jar apps/heartbleed-1.0.1.jar -h`

## Playbook (operator notes)

# The Heartbleed Bug

- **TLS Heartbeat extension:** Keeps connections alive by sending a request and receiving the same payload back.
- **Vulnerability (Heartbleed):**
    - OpenSSL failed to validate the **payload length**.
    - Malicious clients could request more data than sent.
    - Server would leak memory contents in its response.
- **Impact:** Memory leaks could expose sensitive data, including **private keys**.
- **Severity:** Heartbeat was enabled by default → millions of servers affected → massive security crisis.

### **Tools & Prevention**

```python
java -jar apps/heartbleed-1.0.1.jar -h

java -jar heartbleed-1.0.1.jar -connect 127.0.0.1:443

java -jar heartbleed-1.0.1.jar -connect 127.0.0.1:443 -executeAttack -heartbeats 10 -heartbeats 10
```

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/The Heartbleed Bug.md`
