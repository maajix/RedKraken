---
technique: "nikto"
family: "recon-tools"
severity_hint: "medium"
tags: []
source: "_raw/Auto scanners/nikto.md"
source_sha256: "9b41e7794b3d6e8a8d51e3605fee1b96d999cb514bb6f7a70bcfde3970099ce3"
curator_version: 2
review_status: imported-unreviewed
---

# nikto

> Family: **recon-tools** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: nikto.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: sudo nikto -followredirects -Format htm -o nikto-scan -host https://$DOMAIN`
- `bash: firefox nikto-scan`

## Playbook (operator notes)

# nikto

Verantwortliche/r: Max Randhahn

```bash
export DOMAIN = "example.com"
```

# Run a simple nikto scan

```bash
sudo nikto -followredirects -Format htm -o nikto-scan -host https://$DOMAIN
```

# View the output

```bash
firefox nikto-scan
```

## Source
Original note: `_raw/Auto scanners/nikto.md`
