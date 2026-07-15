---
technique: "cmsmap"
family: "cms"
severity_hint: "medium"
tags: []
source: "_raw/CMS/cmsmap.md"
source_sha256: "4ad7490751566527e3f8640de8dbc83daf51fb1ffeb23f54681f8f59c65159d3"
curator_version: 2
review_status: imported-unreviewed
---

# cmsmap

> Family: **cms** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: cmsmap https://$DOMAIN -D -o cmsmap-scan`

## Playbook (operator notes)

# cmsmap

Verantwortliche/r: Max Randhahn

[https://github.com/dionach/CMSmap](https://github.com/dionach/CMSmap)

```bash
export DOMAIN = "example.com"
```

# Run a simple cmsmap scan

- If we know the CMS we can set it via `-f W/D/J`
    - Wordpress, Drupal, Joomla
- Do a full scan using large plugin lists `-F`

```bash
cmsmap https://$DOMAIN -D -o cmsmap-scan
```

## Source
Original note: `_raw/CMS/cmsmap.md`
