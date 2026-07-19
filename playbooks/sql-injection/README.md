---
id: modern-relational-query-boundaries
title: Relational Query Boundaries
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: high
---

# Relational Query Boundaries

## Threat model

SQL injection occurs when externally influenced data crosses into SQL syntax,
query structure, identifiers, ordering, or delayed dynamic SQL. Trace direct and
second-order inputs through ORM/raw-query boundaries, storage, jobs, reports,
imports, and database-specific interpreters.

## Safe detection

1. Map the exact request parameter to the query boundary. Start with a syntax
   probe and a matched true/false or error pair that changes one expression only.
2. Repeat controls to separate query behavior from caching, rate limiting,
   unstable data, and generic errors. Use a bounded time pair only when boolean
   or error evidence cannot confirm the behavior.
3. Test second-order paths with a disposable synthetic record and one authorized
   consumer. Preserve ingress, stored representation, downstream query, output,
   and cleanup.
4. Before automation, save a redacted exact HTTP request and mark one injection
   point. Replay one parameter with one thread, level 1, risk 1, bounded
   techniques/time, native rate controls, and full local output capture.
5. Database file access, writes, stacked destructive statements, bulk dumps,
   credential extraction, OOB callbacks, and OS execution are escalation-gated.

## Confirmation and evidence

Confirm a repeatable query-semantic differential, database-specific error, or
bounded timing effect with matched negatives. Save exact redacted request,
parameter, repetitions/timings, distinguishing responses or hashes, inferred
query context, tool version/options, raw-output path, and cleanup.

## Remediation

Use parameterized statements and typed query-builder APIs for values; allowlist
identifiers, sort keys, and operators that cannot be parameterized; eliminate
dynamic SQL and unsafe raw-query escape hatches; preserve types across storage;
use least-privilege database roles; normalize errors; and regression-test both
direct and delayed consumers.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Advanced SQLi Techniques](sqli-advanced-sqli-techniques.md) — severity hint: critical
- [Advanced SQLMap](sqli-advanced-sqlmap.md) — severity hint: critical
- [Blind SQL Injection](sqli-blind-sql-injection.md) — severity hint: critical
- [Custom Tampering](sqli-custom-tampering.md) — severity hint: critical
- [Identifying Vulnerabilities](sqli-identifying-vulnerabilities.md) — severity hint: critical
- [Intro to MSSQL/SQL Server](sqli-intro-to-mssql-sql-server.md) — severity hint: critical
- [Leaking NetNTLM Hashes](sqli-leaking-netntlm-hashes.md) — severity hint: critical
- [Out-of-Band DNS](sqli-out-of-band-dns.md) — severity hint: critical
- [PostgreSQL-Specific Techniques](sqli-postgresql-specific-techniques.md) — severity hint: critical
- [Remote Code Execution](sqli-remote-code-execution.md) — severity hint: critical
- [SQLi](sqli.md) — severity hint: critical
- [Time-based SQLi](sqli-time-based-sqli.md) — severity hint: critical
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP WSTG: Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
