---
technique: "Clientside PP"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/Prototype Pollution/Clientside PP.md"
source_sha256: "7eeb1d65bf23ad7ccbdfb4b12f52a96f9328aacc8d710bbf605c317af696d774"
curator_version: 2
review_status: imported-unreviewed
---

# Clientside PP

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- (no code blocks in this note)

## Playbook (operator notes)

# Clientside PP

`__proto__[srcdoc][]=<script>window.location%3d"/poc.php";</script>`

- Script gadgets are legitimate and benign JavaScript code that can be used in combination with a different attack vector to achieve XSS
- In particular, we are interested in script gadgets that lead to XSS if the prototype object is manipulated
    - https://github.com/BlackFan/client-side-prototype-pollution#script-gadgets
    - https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md
- We can use Dominvador (Burp browser) to find gadgets as well

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution/Clientside PP.md`
