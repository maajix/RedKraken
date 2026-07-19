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
- `bash: export DOMAIN="example.com"`
- `bash: droopescan scan drupal -u https://$DOMAIN -t 32`

## Playbook (operator notes)

# Drupal

[Drupal](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal)

[https://github.com/SamJoan/droopescan](https://github.com/SamJoan/droopescan)

```bash
export DOMAIN="example.com"
```

# Run a simple droopscan

```bash
droopescan scan drupal -u https://$DOMAIN -t 32
```

## HackTricks methodology enrichment

### Discovery and version evidence

- Confirm Drupal using several indicators: `/core/`, `/sites/default/`, public
  changelog/readme files, generator metadata, and Drupal-specific cookies or
  response behavior. A single path is not sufficient attribution.
- Gather version evidence from core assets and public metadata, then enumerate
  themes and modules from HTML, JavaScript, CSS, lock/manifest files, and exposed
  module paths. Match CVEs to the installed component and version, not merely to
  Drupal as a product.
- Check `robots.txt`, public files, JSON/API routes, and error pages for hidden
  routes or configuration disclosure. Keep directory discovery bounded and
  respect the engagement's rate policy.

### Identity and content checks

- Compare login, registration, author pages, password reset, and API responses
  for username enumeration with controlled accounts and alternating control
  requests.
- Test content, file, revision, preview, and administrative routes across the
  role matrix. Drupal route access and object access can diverge; verify both.
- Run `droopescan` through the harness scope controls and retain the raw output,
  but manually reproduce each security claim before recording a finding.

### Escalation gate

Module/theme installation, PHP or template editing, credential attacks, and
published RCE chains are state-changing or code-executing. Stop at version plus
prerequisite confirmation unless explicitly authorized, and use an inert marker
with cleanup evidence when exploitation is approved.

HackTricks source: [Drupal](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/drupal/index.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/network-services-pentesting/pentesting-web/drupal/README.md)).

## Source
Original note: `_raw/CMS/Drupal.md`
