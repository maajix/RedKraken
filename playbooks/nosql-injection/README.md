---
id: modern-nosql-operator-injection
title: NoSQL Operator, Query-Shape, and Type Injection
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# NoSQL Operator, Query-Shape, and Type Injection

## Threat model

Trace query strings, form fields, JSON, GraphQL inputs, filters, sort/select
objects, and deserialized values into document, key-value, search, or graph query
builders. Test both operator injection and parser/type changes that alter query
shape without requiring a literal query-language string.

## Safe detection

1. Seed two synthetic records with known positive/negative attributes and capture
   a legitimate lookup or filter. Establish response and timing baselines.
2. Change one input from scalar to object, array, null, boolean, duplicate key, or
   nested property. Where the datastore supports operators, use only a harmless
   boolean selector against the seeded values.
3. Compare true/false pairs for authentication, object scope, count, result set,
   error, and normalized timing. A parser error or accepted object alone is a lead.
4. Test alternate encodings and transport parsers only to determine whether they
   construct the same typed value. Keep regex patterns trivial and bounded; do
   not use expensive expressions or production-data enumeration.
5. For blind behavior, extract only one synthetic bit/character with a negative
   control. JavaScript/code execution operators, file access, and server-side
   expressions are exploitation and remain RoE-gated.

## Confirmation and evidence

Confirm a stable query-result, authentication, or authorization differential
against the synthetic records caused by operator/query-shape injection. Save the
typed request representation, minimized true/false pair, normalized responses,
datastore/query-builder evidence when available, and cleanup.

## Remediation

Enforce scalar/object schemas before query construction; reject unknown keys and
operators; build queries through typed allowlisted APIs; separate user filters
from authorization predicates; disable server-side expression features; and cap
query complexity, regex, result sizes, and execution time.

## Sources

- [PortSwigger Web Security Academy: NoSQL injection](https://portswigger.net/web-security/nosql-injection)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- [OWASP Node.js Security Cheat Sheet: input validation](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
