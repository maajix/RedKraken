---
id: modern-identity-parser-differentials
title: Identity Parser and Canonicalization Differentials
family: auth-session
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Identity Parser and Canonicalization Differentials

## Threat model

Identity data often crosses several parsers before it becomes an authorization
decision: browser, application validator, identity provider, XML/signature
library, account store, tenant mapper, and mail transport. Test the whole pipeline.
The security invariant is that every component agrees on the same identity and,
for signed messages, the application consumes exactly the element that was
validated.

## Safe detection

1. With tester-owned accounts and domains, map the raw value and the value after
   each parse, normalization, case-fold, Unicode conversion, alias expansion,
   database lookup, SSO claim mapping, and mail delivery step.
2. For email-based tenant gates, invitations, recovery, and account linking,
   compare quoted local-parts, comments, display names, internationalized
   addresses, encoded words, aliases, and unusual separators one class at a time.
   Do not use an address unless the operator controls its final delivery.
3. Check whether uniqueness and authorization use the same canonical form.
   Attempt a collision only between two tester-controlled accounts and verify
   which mailbox and stored principal each component selected.
4. For SAML, mutate a valid tester assertion one structural feature at a time:
   element/attribute duplication, ID/reference placement, namespaces, comments or
   CDATA, DTD presence, and canonicalization boundaries. Reject any document for
   which validation and claim extraction do not resolve to the same node.
5. Compare parser output before attempting bypass. Stop at a minimal test-account
   login, link, or tenant-boundary proof; never target an employee or real user.

## Confirmation and evidence

Save the raw input, every observed normalized representation, parser/library
versions, delivery destination, signed-reference target, consumed assertion node,
and resulting tester identity. A strange accepted syntax without a cross-component
disagreement is not a finding.

## Remediation

Parse once and pass a typed canonical identity forward; use one canonicalization
policy for uniqueness and authorization; do not infer trust from an email suffix;
bind invitations and account links to a verified immutable principal. For SAML,
use a fully patched library, strict schemas, reject ambiguous XML, verify a single
expected signature/reference, and consume only the verified element.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [SAML](saml.md) — severity hint: high
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [Splitting the Email Atom](https://portswigger.net/research/splitting-the-email-atom)
- [RFC 5322: Internet Message Format](https://www.rfc-editor.org/rfc/rfc5322.html)
- [RFC 6531: SMTP Extension for Internationalized Email](https://www.rfc-editor.org/rfc/rfc6531.html)
- [SAML Roulette: parser round trips and namespace confusion](https://portswigger.net/research/saml-roulette-the-hacker-always-wins)
- [The Fragile Lock: novel SAML parser and canonicalization bypasses](https://portswigger.net/research/the-fragile-lock)
