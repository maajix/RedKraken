---
technique: "Drupal"
family: "cms"
severity_hint: "medium"
tags: []
source: "_raw/CMS/Drupal.md"
source_sha256: "501785b20c0ad5b1e8f299f55f9fb2f8acd2b68e08ac333be517998a9b50fa40"
curator_version: 2
review_status: imported-unreviewed
---

# Drupal

> Family: **cms** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: droopescan scan drupal -u https://$DOMAIN -t 32`

## Playbook (operator notes)

# Drupal

Verantwortliche/r: Max Randhahn

[Drupal](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal)

[https://github.com/SamJoan/droopescan](https://github.com/SamJoan/droopescan)

```bash
export DOMAIN = "example.com"
```

# Run a simple droopscan

```bash
droopescan scan drupal -u https://$DOMAIN -t 32
```

## Source
Original note: `_raw/CMS/Drupal.md`
