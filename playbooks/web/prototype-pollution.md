---
technique: "Prototype Pollution"
family: "client-side"
severity_hint: "medium"
tags: ["JavaScript", "Account Takeover", "XSS", "403", "Remote Code Execution", "HTTP", "JS"]
source: "_raw/Web attacks/Web Attacks/Prototype Pollution.md"
source_sha256: "207e2bcc7b9d9d33acbcddea3270df61914b9ea56ff0e05246a6880e59fe8652"
curator_version: 2
review_status: imported-unreviewed
---

# Prototype Pollution

> Family: **client-side** · Severity hint: **medium** · Tags: JavaScript, Account Takeover, XSS, 403, Remote Code Execution, HTTP, JS
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- (no code blocks in this note)

## Playbook (operator notes)

# Prototype Pollution

<aside>
💡

⚠️ PP can break the whole web page, be carefull on live targets!

Check the loaded libraries, then check if we can find a PP for the loaded version. We can then check via the console `Object.prototype` if the PP was successful. We can then search for gadgets that result in XSS for those libs.

</aside>

Whitebox_Attacks_Module_Cheat_Sheet.pdf

https://github.com/BlackFan/client-side-prototype-pollution#prototype-pollution

https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/jquery-deparam.md

https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md

https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets

# Lecture

**JavaScript Objects & Prototypes**

**Introduction to Prototype Pollution**

**Privilege Escalation**

**Remote Code Execution**

**Filter Bypasses**

Clientside PP

Remarks

## Source
Original note: `_raw/Web attacks/Web Attacks/Prototype Pollution.md`
