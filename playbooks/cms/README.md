---
id: modern-cms-extension-platform-boundaries
title: CMS Core, Extension, Content, and Update Boundaries
family: cms
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# CMS Core, Extension, Content, and Update Boundaries

## Threat model

Model the CMS as an extensible platform: core, extensions/themes, roles,
multisite/tenants, content states, media/filesystem, templates, alternate APIs,
background jobs, cache, installer/updater, package registry, and deployment
credentials. The same action often has multiple UI and non-UI entry points.

## Safe detection

1. Passively inventory exact core, plugin/module, theme and runtime versions from
   authorized source/admin data, shipped assets, manifests, lockfiles and SBOMs.
   Remove false matches caused by disabled, vendored, or unshipped components.
2. Build a role x site/tenant x content/object x action x workflow-state matrix
   with test users and content. Cover drafts, revisions, previews, private,
   scheduled, archived/deleted, media, users, settings and ownership transitions.
3. Replay UI actions through REST/GraphQL, AJAX/RPC, feeds/oEmbed, preview, admin,
   import/export, webhook and scheduled-job routes. Verify authoritative state;
   a status code or hidden menu is not an authorization control.
4. Map upload/media/archive, template/editor, backup/restore, and install/update
   paths with inert files on a disposable instance. Do not upload executable code,
   enable editors, publish content, or update production as the default proof.
5. Validate advisories only when exact affected version/configuration and the
   vulnerable behavior are reachable. Route the proof through the relevant
   deeper family and retain component/advisory context.

## Confirmation and evidence

Confirm a role/site/content boundary violation, inert file reaching an executable
or privileged path, exposed sensitive backup/config, or exactly applicable and
reachable component flaw. Save inventory provenance, role/content matrix,
request/response and before/after state, component path/version, advisory range,
negative control, and cleanup.

## Remediation

Minimize and promptly update core/extensions; inventory/SBOM every deployed
component; enforce authorization in shared domain services and all alternate
routes; isolate tenants and executable files; disable production code editors;
protect preview/cron/update tokens; verify packages; restrict filesystem and
installer privileges; and regression-test roles and content states after updates.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Drupal](cms-drupal.md) — severity hint: medium
- [Joomla](cms-joomla.md) — severity hint: medium
- [Wordpress](cms-wordpress.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [WordPress Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [Drupal security advisories](https://www.drupal.org/security)
- [Joomla Security Centre](https://developer.joomla.org/security-centre.html)
- [OWASP WSTG: Fingerprint Web Application Framework](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
