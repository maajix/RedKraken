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
- `bash: export DOMAIN="example.com"`
- `bash: blc -rof --filter-level 3 <https://$DOMAIN> | grep -i broken`

## Playbook (operator notes)

# Broken-Link Hijacking

[Free Broken Link Checking Tool](https://www.deadlinkchecker.com/)

[Free Broken Link Checker - Online Tool](https://brokenlinkcheck.com/)

[Free Broken Link Checker - Dead Link Checking Tool by Ahrefs](https://ahrefs.com/broken-link-checker)

```bash
export DOMAIN="example.com"
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

## HackTricks methodology enrichment

Separate a dead reference from an exploitable ownership gap:

1. Inventory external links from rendered HTML, source, JavaScript bundles,
   stylesheets, manifests, emails, and authenticated flows. Preserve the source
   page and the exact user-visible context.
2. Resolve the hostname and follow redirects without leaving engagement scope.
   Classify NXDOMAIN, dangling DNS to a third-party service, expired domain,
   deleted social handle/repository, and ordinary HTTP failure separately.
3. For third-party platforms, match the provider's current unclaimed-resource
   fingerprint and verify that the referenced tenant/resource name is actually
   available. A generic 404 or provider banner is not enough.
4. Demonstrate impact from the trust relationship: script/style loading,
   password-reset or OAuth allowlisting, security documentation, downloads, or a
   high-trust social/support link. Broken prose links alone are usually low risk.

Do not register a domain, claim a cloud tenant, create a social account, or upload
content without explicit approval; those actions spend money or change external
state. Prefer DNS/HTTP evidence and provider documentation, or use a
tester-controlled equivalent where the program accepts it.

HackTricks source: [Domain and subdomain takeover](https://hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/pentesting-web/domain-subdomain-takeover.md)).

## Source
Original note: `_raw/Web attacks/Web Attacks/Broken-Link Hijacking.md`
