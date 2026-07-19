---
technique: "Verb Tampering"
family: "http-protocol"
severity_hint: "high"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering.md"
curator_version: 2
review_status: imported-unreviewed
---

# Verb Tampering

> Family: **http-protocol** · Severity hint: **high** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: curl.

## Overview

HTTP verb tampering happens when a server-side control (an auth rule, a security filter) is scoped to one HTTP method — usually `GET` — while other methods (`HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`) reach the same resource unchecked. Enumerate the allowed verbs, then swap methods on a protected/filtered request to see whether the check silently doesn't apply.

Commonly used HTTP verbs:

| Verb | Description |
| --- | --- |
| HEAD | Identical to a GET request, but its response only contains the `headers`, without the response body |
| PUT | Writes the request payload to the specified location |
| DELETE | Deletes the resource at the specified location |
| OPTIONS | Shows different options accepted by a web server, like accepted HTTP verbs |
| PATCH | Apply partial modifications to the resource at the specified location |

## Bypassing Basic Auth

Many automated scanners reliably catch verb-tampering caused by insecure *server configuration*, but usually miss the insecure-*coding* variant.

Exploit approach:
- Intercept the request in Burp Suite.
- Identify the HTTP method.
- Change the method and see if the app behaves differently (e.g. an auth-gated page now responds).
- Enumerate allowed methods directly:

```bash
$ curl -i -X OPTIONS http://SERVER_IP:PORT/
HTTP/1.1 200 OK
Date:
Server: Apache/2.4.41 (Ubuntu)Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

Insecure server configuration is the root cause of most of these. Example vulnerable Apache config:

```xml
<Limit GET POST>    Require valid-user</Limit>
```

`<Limit GET POST>` only applies `Require valid-user` to `GET`/`POST` — a request using `HEAD` (or any other verb) bypasses the authentication entirely.

## Bypassing Security Filters

The insecure-coding variant: a developer patches a vulnerability (e.g. SQLi) with a regex filter applied to only one method's parameters, e.g.:

```php
$pattern = "/^[A-Za-z\s]+$/";if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";    ...SNIP...
}
```

The filter validates `$_GET["code"]`, but the query itself reads from `$_REQUEST["code"]` — so submitting the same parameter via `POST` (or any method landing in `$_REQUEST` without touching `$_GET`) skips the filter entirely while still reaching the vulnerable query.

To identify and exploit:
- Try to trigger the filter (e.g. attempt an injection payload) and confirm the app blocks it.
- Try the same payload under a different HTTP verb to see whether the filter was only wired to one method.
- In Burp Suite, intercept the request and change the HTTP method to see if it bypasses the filter.

## Prevention

**Insecure configuration** — verb-scoped auth directives affect most modern web servers (`Apache`, `Tomcat`, `ASP.NET`) whenever authorization is limited to a particular set of verbs, leaving the rest unprotected. Vulnerable Apache example:

```xml
<Directory "/var/www/html/admin">    AuthType Basic    AuthName "Admin Panel"    AuthUserFile /etc/apache2/.htpasswd    <Limit GET>        Require valid-user    </Limit></Directory>
```

`<Limit GET>` means `Require valid-user` only applies to `GET` — the same admin page remains reachable via `POST` with no auth. Same class of bug in Tomcat:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

and in ASP.NET:

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

Fix by using the "except" keywords instead of an explicit allow-list: `LimitExcept` in Apache, `http-method-omission` in Tomcat, `add`/`remove` in ASP.NET — these cover every verb except the ones named. As a general rule, consider disabling/denying `HEAD` requests unless the application specifically requires them.

**Insecure coding** is harder to fix generically. Example:

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);    } else {
        echo "Malicious Request Denied!";    }
}
```

`preg_match` correctly rejects unwanted special characters — but only checks `$_POST['filename']`, while the command uses `$_REQUEST['filename']`. The bug isn't the injection filter itself, it's the *inconsistent use of HTTP methods* between the check and the sink. Always validate and consume the same source (method + parameter) consistently across a given code path.

## Source
Original notes:
- `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/1_Introduction_to_HTTP_verb_Tampering_INFO.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/2_Bypassing_Basic_Authentication_INFO.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/3_Bypassing_Security_Filters_INFO.md`
- `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/4_Verb_Tampering_Prevention_INFO.md`
