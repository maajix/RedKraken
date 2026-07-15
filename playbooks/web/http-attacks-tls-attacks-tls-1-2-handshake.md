---
technique: "TLS 1.2 Handshake"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/TLS 1 2 Handshake.md"
source_sha256: "f6a8319d9c8f0bb55d21bf4bdb04e0ab334984701da736dc76c7caae83ee46bc"
curator_version: 2
review_status: imported-unreviewed
---

# TLS 1.2 Handshake

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- (no code blocks in this note)

## Playbook (operator notes)

# TLS 1.2 Handshake

## Cipher Suites

In TLS, cipher suites define the cryptographic algorithms used for a connection. That includes the following information:

- The key exchange algorithm
- The method used for authentication
- The encryption algorithm and mode, which provide confidentiality
- The MAC algorithm, which provides integrity protection

---

- **Handshake purpose:** Establishes connection and negotiates secure channel parameters.
- **ClientHello:**
    - Sent by the client to start the handshake.
    - Contains supported TLS version, list of cipher suites, and other info.
- **ServerHello:**
    - Server selects TLS version (≤ client’s version).
    - Chooses a cipher suite from client’s list.
- **Server Certificate:**
    - Sent to prove the server’s identity.
- **ServerKeyExchange (if PFS used):**
    - Shares fresh key material.
    - Contains key share + signature.
- **ServerHelloDone:**
    - Indicates server finished initial negotiation.
- **ClientKeyExchange:**
    - Client sends its key share.
    - Key exchange completed, both sides derive shared secret.
- **ChangeCipherSpec:**
    - Both client and server send this message.
    - Signals that subsequent communication is encrypted with the shared symmetric key.
- **After handshake:**
    - All application data is encrypted and integrity-protected (MAC).

### Wireshark

`Wireshark /path/to/file.pcap`

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/TLS 1 2 Handshake.md`
