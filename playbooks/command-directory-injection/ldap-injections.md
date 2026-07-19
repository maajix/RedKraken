---
technique: "LDAP Injections"
family: "injection"
severity_hint: "high"
tags: ["LDAP", "Microsoft", "Authentication", "Account Takeover"]
source: "_raw/Web attacks/Web Attacks/LDAP Injections.md"
curator_version: 2
review_status: imported-unreviewed
---

# LDAP Injections

> Family: **injection** · Severity hint: **high** · Tags: LDAP, Microsoft, Authentication, Account Takeover
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Overview

LDAP injection happens when user input is concatenated unsanitized into an LDAP search filter, letting an attacker rewrite the query's boolean logic to bypass authentication or enumerate directory data one character at a time even when no results are ever displayed directly. As with SQL and XPath injection, the fix is proper escaping of filter metacharacters or, better, delegating credential checks to the directory server's own bind operation.

## Auth Bypass

### Foundation

Since the authentication process needs to check the username and the password, an LDAP search filter like the following can be used:

```bash
(&(uid=admin)(userPassword=password123))
```

Depending on the setup of the directory server, the actual search filter might query different attribute types — username might be checked against the `cn` attribute type.

### Exploitation

Think of what can be injected into the search filter to bypass authentication. Because an asterisk is treated as a wildcard character, it can be injected into the password field to match the value without specifying the actual password. Then specify an arbitrary valid username to bypass authentication for that user:

```bash
(&(uid=admin)(userPassword=*))
```

If a valid username is not known, inject a wildcard into the username field as well (most likely logs in as the first result):

```bash
(&(uid=*)(userPassword=*))
```

Substrings can also be used:

```bash
(&(uid=admin*)(userPassword=*))
```

### Bypassing Authentication without Wildcards

Sometimes `*` is blocked by the application. Alter the search filter so that the password check can fail and the search filter still returns a user — use `admin)(|(&` as username and a password of `abc)`:

```bash
(&(uid=admin)(|(&)(userPassword=abc)))
```

## Blind Exploitation

### Methodology

Assume the application has different responses when logging in (user enumeration). Assume this filter: `(&(uid=htb-stdnt)(password=p@ssw0rd))`. Brute-force the characters (also consider special chars like `!` or `@`) one by one starting with an `a`:

- `(&(uid=htb-stdnt)(password=a*))`
- If the username starts with `a`, a "success" message is returned, otherwise a different "failed" response.

If the username `htb-stdnt)(|(description=*` is submitted with a password of `invalid)`, data from different attributes can be targeted:

- `(&(uid=htb-stdnt)(|(description=*)(password=invalid)))`

> Note: Most LDAP attributes are case-insensitive. So if the correct casing is needed, for instance for passwords, it might have to be brute-forced.

Attributes present on an entry can also be enumerated this way.

> Note: Similar to the exploitation of blind XPath injection, it is recommended to write a script to exfiltrate the data.

## Prevention

### General Remarks

While many web developers are aware of SQL injection vulnerabilities due to the common use of SQL databases in web applications, LDAP injection is a much rarer type of vulnerability, and thus there is less awareness about it. Therefore, LDAP injection vulnerabilities potentially exist whenever LDAP integration is used in web applications, even though there are simple countermeasures. To prevent LDAP injection vulnerabilities, the following special characters need to be escaped:

- The parenthesis `(` needs to be escaped as `\28`
- The parenthesis `)` needs to be escaped as `\29`
- The asterisk needs to be escaped as `\2a`
- The backslash `\` needs to be escaped as `\5c`
- The null byte needs to be escaped as `\00`

### PHP Example

In many languages, there are predefined functions that implement LDAP escaping. In PHP, this function is called `ldap_escape`. Check out the documentation [here](https://www.php.net/manual/en/function.ldap-escape.php).

As an example, consider the following simplified code that is vulnerable to LDAP injection:

```php
// ldap connection
const LDAP_HOST = "localhost";
const LDAP_PORT = 389;
const LDAP_DC = "dc=example,dc=htb";
const LDAP_DN = "cn=ldapuser,dc=example,dc=htb";
const LDAP_PASS = "ldappassword";

// connect to server
$conn = ldap_connect(LDAP_HOST, LDAP_PORT);
if (!$conn) {
    exit('LDAP connection failed');
}

// bind operation
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
$bind = ldap_bind($conn, LDAP_DN, LDAP_PASS);
if (!$bind) {
    exit('LDAP bind failed');
}

// search operation
$filter = '(&(cn=' . $_POST['username'] . ')(userPassword=' . $_POST['password'] . '))';
$search = ldap_search($conn, LDAP_DC, $filter);
$entries = ldap_get_entries($conn, $search);

if ($entries['count'] > 0) {
    // successful login
    <SNIP>
} else {
    // login failed
    <SNIP>
}
```

In the search operation, the web application inserts user input without any sanitization, leading to LDAP injection as exploited above. To prevent this, simply call the function `ldap_escape` when inserting the user input into the search filter. The corresponding line of code should thus look like this:

```php
$filter = '(&(cn=' . ldap_escape($_POST['username']) . ')(userPassword=' . ldap_escape($_POST['password']) . '))';
```

### Best Practices

While proper sanitization prevents LDAP injection entirely, there are some further best practices to follow whenever LDAP is used in a web application. First, the account used to bind to the DS should be given the `least privileges` required to perform the search operation for its specific task. This limits the amount of data an attacker can access in the event of an LDAP injection vulnerability.

Furthermore, when using LDAP for authentication, it is more secure to perform a bind operation with the credentials provided by the user instead of performing a search operation. Since the DS checks the credentials when performing a bind operation, the authentication process is delegated to the DS to handle it. This way, there is no LDAP search filter where LDAP injection can occur. To do this, the example code above needs to change to look like this:

```php
// ldap connection
const LDAP_HOST = "localhost";
const LDAP_PORT = 389;
const LDAP_DC = "dc=example,dc=htb";

// user credentials
$dn = "cn=" . ldap_escape($_POST['username'], "", LDAP_ESCAPE_DN) . ",dc=example,dc=htb";
$pw = $_POST['password'];

// connect to server
$conn = ldap_connect(LDAP_HOST, LDAP_PORT);
if (!$conn) {
    exit('LDAP connection failed');
}

// bind operation
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
$bind = ldap_bind($conn, $dn, $pw);
if ($bind) {
    // successful login
    <SNIP>
} else {
    // login failed
    <SNIP>
}
```

Lastly, anonymous authentication, also called `anonymous binds`, should be disabled on the DS so that only authenticated users can perform any operation.

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/LDAP Injections.md`
- `_raw/Web attacks/Web Attacks/LDAP Injections/LDAP - Authentication Bypass.md`
- `_raw/Web attacks/Web Attacks/LDAP Injections/LDAP - Blind Exploitation.md`
- `_raw/Web attacks/Web Attacks/LDAP Injections/LDAP Injection Prevention.md`
