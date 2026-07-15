---
technique: "POODLE & BEAST"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/POODLE & BEAST.md"
source_sha256: "45cfe3885fd599bc5058f2df9367031c98ebc03dea30f09c550ba37e77fd437a"
curator_version: 2
review_status: imported-unreviewed
---

# POODLE & BEAST

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: sudo apt install maven`

## Playbook (operator notes)

# POODLE & BEAST

### **Padding in SSL 3.0**

- **POODLE & BEAST:** Padding oracle attacks on SSL 3.0 enabling decryption of network traffic (e.g., credentials).
- **Requirements:** Attacker must intercept ciphertext and communicate with the target server.
- **SSL 3.0 padding scheme:**
    - Last byte = padding length (excl. itself).
    - Other padding bytes = arbitrary values.
- **Example (8-byte block, 4-byte plaintext):**
    - Plaintext: `DE AD BE EF` → needs 4 padding bytes.
    - Result: `DE AD BE EF 00 00 00 03`.
- **Note:** Even if plaintext already fits block size, a full block of padding is added.

---

### **POODLE Attack**

- **Discovered:** 2014 — broke SSL 3.0 entirely.
- **Attack method:**
    - Attacker forces victim to send requests with a full padding block.
    - Last padding byte (length) is known.
    - Attacker modifies last ciphertext block → observes server response.
- **Server behavior:**
    - Wrong padding length → MAC error.
    - Correct padding length → MAC check passes (no error).
- **Result:**
    - Leaks intermediary CBC values → attacker recovers plaintext bytes recursively.
- **Root cause:**
    - Arbitrary padding bytes allowed except last length byte.
    - Distinguishable server errors reveal padding correctness.

---

### **BEAST Attack**

- **Discovered:** 2011, targets SSL/TLS using CBC mode.
- **Attack method:**
    - Attacker intercepts a valid ciphertext.
    - Crafts modified ciphertexts to deduce plaintext block contents.
    - Uses *plaintext injection* to shift data so only one unknown byte remains.
    - Enables brute-forcing plaintext **byte by byte**.
- **Limitation:**
    - Brute-forcing entire blocks is infeasible without injection trick.
- **Practicality:**
    - Mostly theoretical → real-world exploitation is hard.
    - Requires bypassing browser **same-origin policy**, reducing real risk.

---

### **Tools & Prevention**

[https://github.com/tls-attacker/TLS-Breaker](https://github.com/tls-attacker/TLS-Breaker)

```bash
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

---

### Prevention

POODLE can be prevented by disabling the use of SSL 3.0 entirely. Even if a web server supports newer TLS versions, a client might be able to force the use of SSL 3.0 by manipulating handshake messages. Therefore, SSL 3.0 should be completely disabled and not be supported even for legacy reasons.
`SSLProtocol all -SSlv3`

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/POODLE & BEAST.md`
