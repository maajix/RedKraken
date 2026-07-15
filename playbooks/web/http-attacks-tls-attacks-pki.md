---
technique: "PKI"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/PKI.md"
source_sha256: "59c6f273c9aa585e6785fe0d0c268dd1cf217ba9a7f09e90a91cebbdb024af3d"
curator_version: 2
review_status: imported-unreviewed
---

# PKI

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: openssl.

## Quick index — payloads & commands in this note
- `python: # Generate a key-pair`

## Playbook (operator notes)

# PKI

### Certificates

- The purpose of certificates is to bind public keys to an identity
- Proves the identity of the pub key owner

### OpenSSL

```python
# Generate a key-pair
openssl genrsa -out key.pem 2048

# Extract the pub key
openssl rsa -in key.pem -pubout > rsa_pub.pem

# Encrypt file
openssl pkeyutl -encrypt -inkey rsa_pub.pem -pubin -in msg.txt -out msg.enc
# Decrypt file 
openssl pkeyutl -decrypt -inkey rsa.pem -in msg.enc > decrypted.txt

# Download certificate of a webserver
openssl s_client -connect hackthebox.com:443 | openssl x509 > hackthebox.pem
# PEM to DER
openssl x509 -outform der -in hackthebox.pem -out hackthebox.der
# PEM to PKCS#7
openssl crl2pkcs7 -nocrl -certfile hackthebox.pem -out hackthebox.p7

# Self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out selfsigned.pem -sha256 -days 365
```

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/PKI.md`
