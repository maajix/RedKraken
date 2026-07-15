---
id: modern-framework-routing-trust-boundaries
title: Framework-Generated Routes and Internal Routing Trust
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Framework-Generated Routes and Internal Routing Trust

## Threat model

Modern frameworks expose more than the visible page URL: data and component
fetches, prefetch routes, server actions, stream endpoints, rewrites, middleware,
and adapter-specific internal headers. Authorization must hold at the underlying
handler for every transport representation.

## Safe detection

1. Fingerprint the framework and deployment adapter, then inventory generated
   routes and headers from browser traces, bundles, manifests, and official docs.
2. For one protected tester-owned object, compare the normal URL with observed
   data/action/stream/prefetch representations and normalized path/query forms.
3. Supply one routing, rewrite, prefetch, subrequest, or action header at a time.
   Treat client-supplied internal headers as untrusted; use read-only canaries.
4. Invoke discovered server actions or equivalent endpoints as anonymous, peer,
   and owner. Hidden UI, action identifiers, middleware, and layouts are not
   authorization controls.
5. Confirm only when an alternate representation reaches content or an action
   denied through the ordinary route. Gate state changes behind the RoE.

## Confirmation and evidence

Save framework/adapter versions, ordinary and alternate requests, routing headers,
middleware/handler observations, identity, normalized route, response, and final
state. A framework fingerprint or exposed action identifier alone is not a finding.

## Remediation

Patch supported framework versions; strip or authenticate internal routing headers
at the trust boundary; authorize inside every route/action/loader; apply policy to
all generated transport variants; and keep middleware as defense in depth rather
than the sole authorization layer.

## Sources

- [Vercel postmortem: Next.js middleware bypass](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [Next.js segment-prefetch authorization-bypass advisory](https://github.com/vercel/next.js/security/advisories/GHSA-267c-6grr-h53f)
- [Next.js data-security guidance](https://nextjs.org/docs/15/app/guides/data-security)
- [Next.js Server Actions configuration](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions)

