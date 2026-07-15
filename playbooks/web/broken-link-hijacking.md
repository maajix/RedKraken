---
technique: "Broken-Link Hijacking"
family: "client-side"
severity_hint: "low"
tags: ["HTML"]
source: "_raw/Web attacks/Web Attacks/Broken-Link Hijacking.md"
source_sha256: "f8e7b56a72ad79ff061c07a2b00ff72e2a568466c2e2017d55b322178cd88d87"
curator_version: 2
review_status: imported-unreviewed
---

# Broken-Link Hijacking

> Family: **client-side** · Severity hint: **low** · Tags: HTML
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: blc -rof --filter-level 3 <https://$DOMAIN> | grep -i broken`

## Playbook (operator notes)

# Broken-Link Hijacking

[Free Broken Link Checking Tool](https://www.deadlinkchecker.com/)

[Free Broken Link Checker - Online Tool](https://brokenlinkcheck.com/)

[Free Broken Link Checker - Dead Link Checking Tool by Ahrefs](https://ahrefs.com/broken-link-checker)

```bash
export DOMAIN = "example.com"
```

# How to Hunt for Broken Links

1. Run the [Broken Link Checker](https://github.com/stevenvachon/broken-link-checker) in the background:
    
    ```bash
    blc -rof --filter-level 3 <https://$DOMAIN> | grep -i broken
    ```
    
2. While the automated scanner is running, manually check for broken links (Social Media Accounts or external Media) or use free websites that check for broken links.
3. After gathering some links, check if the referred page is one you could control by acquiring the domain, etc.

---

[Broken-Link Hijacking](https://kathan19.gitbook.io/howtohunt/broken-link-hijacking/brokenlinkhijacking)

## Source
Original note: `_raw/Web attacks/Web Attacks/Broken-Link Hijacking.md`
