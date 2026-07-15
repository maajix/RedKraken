# PKI

![image.png](PKI/image.png)

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