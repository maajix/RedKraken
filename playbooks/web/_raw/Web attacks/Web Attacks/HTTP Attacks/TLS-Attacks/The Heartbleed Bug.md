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