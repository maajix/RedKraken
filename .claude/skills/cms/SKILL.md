---
name: cms-platform-attacks
description: Tests CMS and extensible web platforms across core, plugins/modules, themes, multisite, roles, content workflows, uploads, templates, APIs, jobs, installation, and update boundaries.
---

# CMS & Extensible Platform

Start with `playbooks/cms/README.md`, then open the
matching imported WordPress, Drupal, Joomla, or generic CMS notes. Version or
plugin presence is inventory until an affected reachable behavior is verified.

## Attack surfaces

- Core, plugin/module, theme/template, language pack, page builder, editor, media
  processor, form, backup, migration, search, cache, and update components.
- Anonymous/member/author/editor/admin and custom roles across content types,
  drafts, revisions, previews, media, taxonomies, users, settings, and multisite.
- REST/GraphQL/AJAX/RPC/feed/oEmbed/webhook routes, scheduled jobs, CLI/admin
  actions, alternate hosts, preview tokens, and cache variants.
- Install/update/upload/import/backup/restore, package signatures and provenance,
  filesystem ownership, executable upload paths, template/code editing, and
  secret/config exposure.

## Method and safety

1. Build a version and component inventory from passive assets, manifests,
   authenticated admin views, lockfiles/SBOM, and source when authorized. Avoid
   broad username, content, or plugin brute force by default.
2. Use test content and identities to apply the identity/object/action/state
   matrix to UI and every alternate route. Check draft/private/deleted state,
   preview tokens, revisions, multisite/tenant boundaries, and background jobs.
3. Reconcile advisories with exact version/configuration and reachable code. A
   scanner/CVE match alone is not confirmed.
4. Test upload/import/template/update paths with inert files and disposable
   instances. Never install public packages, modify production themes/plugins,
   drop shells, publish content, or trigger production updates without explicit
   authorization.
5. Route findings to the deeper family card (access control, injection, file,
   auth, supply chain, config, client-side) while retaining CMS/component context.

Save core/component versions and sources, role/content/site matrix, exact route,
before/after state, advisory applicability, minimized inert proof, and cleanup.
