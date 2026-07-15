---
technique: "paramspider"
family: "client-side"
severity_hint: "medium"
tags: []
source: "_raw/Web attacks/Web Attacks/XSS/paramspider.md"
source_sha256: "dd3f9a10c00e78087ec859ce3e9429bc916483a7afdc6e7ce4d026614f93bb6f"
curator_version: 2
review_status: imported-unreviewed
---

# paramspider

> Family: **client-side** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: paramspider.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: paramspider -l https://$DOMAIN`

## Playbook (operator notes)

# paramspider

[https://github.com/devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider)

```bash
export DOMAIN = "example.com"
```

# Run paramspider

```bash
paramspider -l https://$DOMAIN
```

## Source
Original note: `_raw/Web attacks/Web Attacks/XSS/paramspider.md`
