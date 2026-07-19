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

## Enrichment — matcher/filter, subdomain & parameter fuzzing (imported-unreviewed, from course notes)
> Added from personal HTB Academy notes; PII scrubbed. Untrusted until reviewed.

### Matcher flags
Match = keep only responses meeting the criterion.

| Flag | Matches |
| ---- | ------- |
| `-mc` | HTTP status codes, or `all` (default: 200,204,301,302,307,401,403) |
| `-ml` | Amount of lines in response |
| `-mr` | Regexp |
| `-ms` | HTTP response size |
| `-mw` | Amount of words in response |

### Filter flags
Filter = drop responses meeting the criterion. Comma-separated lists and ranges accepted.

| Flag | Filters out |
| ---- | ----------- |
| `-fc` | HTTP status codes |
| `-fl` | Amount of lines in response |
| `-fr` | Regexp |
| `-fs` | HTTP response size |
| `-fw` | Amount of words in response |

Typical use: baseline a wrong/uniform response then drop it, e.g. `-fs 900`.

### Subdomain / VHost fuzzing
Fuzz the `Host` header to discover non-public VHosts; `-fs <baseline>` drops the default-page size.

```bash
ffuf -w $WL -u https://target.example/ -H 'Host: FUZZ.target.example' -fs <baseline>
```

### GET parameter fuzzing
Fuzz parameter NAME (baseline wrong-size responses with `-fs`):

```bash
ffuf -w $WL:FUZZ -u https://target.example/example.php?FUZZ=anything -c -fs <baseline>
```

Fuzz parameter VALUE for a known name (e.g. brute an id list):

```bash
ffuf -w $WL:FUZZ -u https://target.example/example.php?id=FUZZ -c -fs <baseline>
```

### POST parameter fuzzing
Fuzz parameter NAME:

```bash
ffuf -w $WL:FUZZ -u https://target.example/example.php -c -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs <baseline>
```

Fuzz parameter VALUE for a known name:

```bash
ffuf -w $WL:FUZZ -u https://target.example/example.php -c -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs <baseline>
```

Tip: try both GET and POST — they can return different results. Confirm hits with `curl`.

## Source
Original note: `_raw/ffuf.md`
