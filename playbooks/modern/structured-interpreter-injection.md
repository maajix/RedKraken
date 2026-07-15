---
id: modern-structured-interpreter-injection
title: Structured, Expression, Format, and Second-order Injection
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Structured, Expression, Format, and Second-order Injection

## Threat model

Trace untrusted data across storage and canonicalization into XML/XPath/XQuery,
XSLT, expression languages, server-side includes, edge-side includes, format
strings, log/message templates, policy/rule engines, search/query DSLs, and later
interpreters, including IMAP/SMTP command and message-header construction. Input
may be safe at ingestion but become code after retrieval,
concatenation, decoding, import/export, or a background job.

## Safe detection

1. Inventory every parser/interpreter and delayed consumer, including scheduled
   jobs, exports, admin views, notifications, logs, reports, templates and
   downstream services. Record data representation at each hop.
2. Use syntax-neutral canaries first, then harmless true/false or arithmetic
   expressions specific to the confirmed interpreter. Change one delimiter,
   operator, namespace, encoding, format directive, or context boundary at a time.
3. For XML/XPath/XSLT, use synthetic nodes and local transforms without external
   entities, files, network functions or recursive expansion. Distinguish parser
   errors from changed query/transform semantics.
4. For SSI/ESI, expression and format strings, prove evaluation with literal or
   arithmetic output only. File include, command, environment, memory disclosure,
   callback and cache-persistent directives remain exploitation-gated.
5. For IMAP/SMTP and generated message headers, use only a harness-owned mail
   server and mailbox. Prove argument/header boundary preservation with a benign
   canary; do not relay, send spam, access other mailboxes, or inject active
   commands into a production mail system.
6. For second-order paths, store a unique canary in a disposable record and
   trigger exactly one authorized downstream consumer. Save the value at ingress,
   storage, retrieval, query/template construction and output; then delete it.

## Confirmation and evidence

Confirm deterministic interpreter evaluation or a query/policy semantic change
with a matched negative control, including the full delayed data path. An error
or reflected delimiter alone is a lead. Save minimized input, representations at
each hop, interpreter/version, true/false or literal output, source-to-sink path,
after-state, and cleanup.

## Remediation

Use typed parameterized APIs and fixed templates/format strings; keep untrusted
data out of code, selectors and policy; encode for the final interpreter/context;
disable dynamic includes/functions; allowlist expression grammar; preserve type
information across storage; validate again at delayed sinks; and test second-
order consumers with regression canaries.

## Sources

- [OWASP WSTG: Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [CWE-91: XML Injection](https://cwe.mitre.org/data/definitions/91.html)
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html)
- [OWASP WSTG: Testing for IMAP SMTP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection)
