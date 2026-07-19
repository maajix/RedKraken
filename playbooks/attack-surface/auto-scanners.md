---
technique: "Auto scanners"
family: "misc"
severity_hint: "medium"
tags: []
source: "_raw/Auto scanners.md"
curator_version: 2
review_status: imported-unreviewed
---

# Auto scanners

> Family: **misc** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: nikto, nuclei, nucleifuzzer.

## Overview

Automated scanner reference covering the background-noise tools run alongside manual testing: `nikto` for general web-server misconfiguration checks, `nuclei` for template-driven vulnerability scanning, and `NucleiFuzzer` for fuzzing-plus-nuclei triage across single or multiple domains. See the per-tool sections below for setup and invocation.

### Nikto

```bash
export DOMAIN = "example.com"
```

Run a simple nikto scan:

```bash
sudo nikto -followredirects -Format htm -o nikto-scan -host https://$DOMAIN
```

View the output:

```bash
firefox nikto-scan
```

### Nuclei

[https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

```bash
export DOMAIN = "example.com"
```

Run a simple nuclei scan:

```bash
nuclei -target $DOMAIN -o nuclei-scan
```

### NucleiFuzzer

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

Run NucleiFuzzer on a single domain:

```bash
sudo nf -d $DOMAIN
```

Run NucleiFuzzer on multiple domains:

```bash
sudo nf -f <domain_list>
```

View the output:

```bash
mv output nuclei-fuzzer-scan && cd nuclei-fuzzer-scan
```

## Source
Original notes:
- `_raw/Auto scanners.md`
- `_raw/Auto scanners/nikto.md`
- `_raw/Auto scanners/Nuclei.md`
- `_raw/Auto scanners/NucleiFuzzer.md`
