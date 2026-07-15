---
technique: "Joomla"
family: "cms"
severity_hint: "medium"
tags: []
source: "_raw/CMS/Joomla.md"
source_sha256: "733d7054a80077a5fc399f14ad5821443df678757bb3d360c30d73fceaeb67ce"
curator_version: 2
review_status: imported-unreviewed
---

# Joomla

> Family: **cms** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: joomscan -u https://$DOMAIN`

## Playbook (operator notes)

# Joomla

[Joomla](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla)

[joomscan | Kali Linux Tools](https://www.kali.org/tools/joomscan/)

```bash
export DOMAIN = "example.com"
```

# Run a simple Joomscan

```bash
joomscan -u https://$DOMAIN
```

## Source
Original note: `_raw/CMS/Joomla.md`
