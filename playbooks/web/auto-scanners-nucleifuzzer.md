---
technique: "NucleiFuzzer"
family: "recon-tools"
severity_hint: "medium"
tags: []
source: "_raw/Auto scanners/NucleiFuzzer.md"
source_sha256: "fc3e57ef48f72551c7ce97dde27d504172f16effc3e42b854583742b79c114b4"
curator_version: 2
review_status: imported-unreviewed
---

# NucleiFuzzer

> Family: **recon-tools** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: nuclei.

## Quick index — payloads & commands in this note
- `bash: git clone https://github.com/0xKayala/NucleiFuzzer.git`
- `bash: export DOMAIN = "example.com"`
- `bash: sudo nf -d $DOMAIN`
- `bash: sudo nf -f <domain_list>`
- `bash: mv output nuclei-fuzzer-scan && cd nuclei-fuzzer-scan`

## Playbook (operator notes)

# NucleiFuzzer

Verantwortliche/r: Max Randhahn

[https://github.com/0xKayala/NucleiFuzzer](https://github.com/0xKayala/NucleiFuzzer)

```bash
git clone https://github.com/0xKayala/NucleiFuzzer.git
cd NucleiFuzzer
sudo chmod +x install.sh
./install.sh
```

```bash
export DOMAIN = "example.com"
```

# Run NucleiFuzzer on a single domain

```bash
sudo nf -d $DOMAIN
```

# Run NucleiFuzzer on multiple domains

```bash
sudo nf -f <domain_list>
```

# View the output

```bash
mv output nuclei-fuzzer-scan && cd nuclei-fuzzer-scan
```

## Source
Original note: `_raw/Auto scanners/NucleiFuzzer.md`
