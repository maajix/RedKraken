---
id: modern-orm-relational-filter-leaks
title: ORM Relational Filter and Query-Shape Leaks
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# ORM Relational Filter and Query-Shape Leaks

## Threat model

An API can serialize only public fields yet still leak hidden or unauthorized data
when user-controlled filters, relation traversal, operators, sorting, aggregation,
or selection shape influence the ORM query. Treat query expressiveness as an
authorization surface, not merely input validation.

## Safe detection

1. Seed a unique synthetic secret in a hidden field on a tester-owned related
   object, plus positive and negative control records.
2. Map accepted filter keys, nested relations, operators, sort/group/aggregate,
   include/select/expand, pagination, and error behavior. Change one query-shape
   feature at a time.
3. Ask boolean questions about the synthetic value through visible result
   membership or count. Check `contains`, prefix/suffix, comparisons, relation
   quantifiers (`some`/`every`/`none`), negation, and nested joins.
4. Compare owner, peer, cross-tenant, and privileged identities. Ensure relation
   traversal cannot escape the row-level scope applied to the base model.
5. Use a tiny bounded sample for timing or error oracles and pair every candidate
   concurrently with a negative control where the protocol permits it. Reverse
   request order and require statistical separation; do not enumerate production
   secrets or create expensive wildcard/regex queries.

## Confirmation and evidence

Confirm by recovering a few characters of the synthetic canary or distinguishing
its value with a repeatable result/count/error/timing oracle. Save the schema or
inferred relation, exact filter, identity, normalized response, control pair,
query count, and timing statistics when applicable.

## Remediation

Translate public filters into an explicit allowlisted query AST; allowlist fields,
relations, operators, depth, and cost; apply tenant/object policy to every joined
model; separate filtering from output selection; cap query complexity; and avoid
passing request objects directly into ORM APIs.

## Sources

- [plORMbing your Django ORM](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [plORMbing your Prisma ORM with Time-based Attacks](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [Listen to the Whispers: web timing attacks that actually work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)
- [Prisma relation filters](https://www.prisma.io/docs/orm/prisma-client/queries/relation-queries#relation-filters)
- [Django QuerySet API](https://docs.djangoproject.com/en/stable/ref/models/querysets/)
