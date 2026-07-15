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

![image.png](TLS%201%202%20Handshake/image.png)

### Wireshark

`Wireshark /path/to/file.pcap`

![image.png](TLS%201%202%20Handshake/image%201.png)

![image.png](TLS%201%202%20Handshake/image%202.png)

![image.png](TLS%201%202%20Handshake/image%203.png)

![image.png](TLS%201%202%20Handshake/image%204.png)