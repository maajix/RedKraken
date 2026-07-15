---
technique: "3_Bypassing_Security_Filters_INFO"
family: "http-protocol"
severity_hint: "low"
tags: []
source: "_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/3_Bypassing_Security_Filters_INFO.md"
source_sha256: "a921c2c08438e7b493a625ec5d0a0521a4d3f020014dab7aa8ff9737c395e707"
curator_version: 2
review_status: imported-unreviewed
---

# 3_Bypassing_Security_Filters_INFO

> Family: **http-protocol** · Severity hint: **low** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- (no code blocks in this note)

## Playbook (operator notes)

# 3_Bypassing_Security_Filters_INFO

## Identify

- Try to for example create a new file
- See if the application identifies inection attempts
- Try ab HTTP verb Tampering attack to see if we can bypass the security filter altogether

## Exploit

- Intercept the request in Burp Suite
- Change the HTTP methods to any other verb
- See if it bypasses the filter

## Source
Original note: `_raw/Web attacks/Web Attacks/HTTP Attacks/Verb Tampering/3_Bypassing_Security_Filters_INFO.md`
