---
technique: "ffuf"
family: "misc"
severity_hint: "medium"
tags: []
source: "_raw/ffuf.md"
source_sha256: "f97c4d5666b3319afef5b96772545f3dc9a3da85ae26e9fb76d7aea10bc835c3"
curator_version: 2
review_status: imported-unreviewed
---

# ffuf

> Family: **misc** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: ffuf.

## Quick index — payloads & commands in this note
- `bash: ffuf -w $WL -u https://$DOMAIN/FUZZ -H "X-Custom-Header: FUZZ"`
- `bash: ffuf -w $WL -u https://$DOMAIN/FUZZ -X GET -H "User-Agent: FUZZ"`
- `bash: ffuf -w $WL -u https://$DOMAIN/ -X FUZZ`
- `bash: ffuf -w $WL -u https://$DOMAIN/ -X POST -H "Content-Type: FUZZ" -d '{"data":"example"}'`

## Playbook (operator notes)

# ffuf

Verantwortliche/r: Max Randhahn

# Header Brute-Forcing

```bash
ffuf -w $WL -u https://$DOMAIN/FUZZ -H "X-Custom-Header: FUZZ"
```

# WAF Bypass

```bash
ffuf -w $WL -u https://$DOMAIN/FUZZ -X GET -H "User-Agent: FUZZ"
```

# HTTP Request Smuggling

```bash
ffuf -w $WL -u https://$DOMAIN/ -X FUZZ
```

# Content Type Fuzzing

```bash
ffuf -w $WL -u https://$DOMAIN/ -X POST -H "Content-Type: FUZZ" -d '{"data":"example"}'
```

## Source
Original note: `_raw/ffuf.md`
