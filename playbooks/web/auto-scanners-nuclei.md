---
technique: "Nuclei"
family: "recon-tools"
severity_hint: "medium"
tags: []
source: "_raw/Auto scanners/Nuclei.md"
source_sha256: "6908c0c1cd7a266b5927d3f83208b5e411cfdf71d16606c8a7ac346de243f990"
curator_version: 2
review_status: imported-unreviewed
---

# Nuclei

> Family: **recon-tools** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: nuclei.

## Quick index — payloads & commands in this note
- `bash: export DOMAIN = "example.com"`
- `bash: nuclei -target $DOMAIN -o nuclei-scan`

## Playbook (operator notes)

# Nuclei

Verantwortliche/r: Max Randhahn

[https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

```bash
export DOMAIN = "example.com"
```

# Run a simple nuclei scan

```bash
nuclei -target $DOMAIN -o nuclei-scan
```

## Source
Original note: `_raw/Auto scanners/Nuclei.md`
