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
- `bash: export DOMAIN="example.com"`
- `bash: joomscan -u https://$DOMAIN`

## Playbook (operator notes)

# Joomla

[Joomla](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla)

[joomscan | Kali Linux Tools](https://www.kali.org/tools/joomscan/)

```bash
export DOMAIN="example.com"
```

# Run a simple Joomscan

```bash
joomscan -u https://$DOMAIN
```

## HackTricks methodology enrichment

### Discovery and version evidence

- Confirm Joomla through multiple signals: generator metadata, characteristic
  `/administrator/` behavior, templates, language files, and paths disclosed by
  `robots.txt`. Do not infer a vulnerable version from one banner.
- Collect passive version evidence from public manifests, static asset versions,
  changelog/readme files, response headers, and extension metadata. Preserve the
  exact URL and response for each version claim.
- Enumerate templates, components, modules, plugins, and exposed backup or
  configuration artifacts. Map every component to a version before researching
  CVEs; third-party extensions are often the useful boundary.

### Authentication and API checks

- Compare the public site and `/administrator/` for username enumeration,
  password-reset behavior, MFA/recovery gaps, and session invalidation using only
  approved test accounts.
- Probe documented Joomla API routes with unauthenticated and least-privilege
  roles. An information endpoint is a finding only when it exposes data beyond
  the intended public contract.
- Run `joomscan` through the harness scope controls and manually validate every
  result; scanner fingerprints and missing headers are leads, not proof.

### Escalation gate

Template editing, extension installation, credential guessing, or known-exploit
execution changes site state and may execute code. Stop after proving the
prerequisites unless the rules of engagement explicitly authorize that action and
include restoration evidence.

HackTricks source: [Joomla](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/joomla.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/network-services-pentesting/pentesting-web/joomla.md)).

## Source
Original note: `_raw/CMS/Joomla.md`
