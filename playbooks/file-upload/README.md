---
id: modern-file-upload-processing-boundaries
title: File Upload Processing Boundaries
family: ssrf-xxe-file
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: high
---

# File Upload Processing Boundaries

## Threat model

Treat upload as a pipeline: authorization, multipart parsing, filename
canonicalization, extension/media/magic-byte validation, transformation,
scanning, storage, delayed processing, archive extraction, retrieval, and any
execution-capable consumer. Each stage can interpret the same bytes differently.

## Safe detection

1. Map accepted size, filename, extension, declared media type, detected type,
   storage key, transform jobs, retrieval headers, tenancy checks, and cleanup.
2. Use only inert tester-owned canaries. Vary one property at a time: case,
   Unicode normalization, multiple extensions, declared/detected type mismatch,
   duplicate multipart fields, filename separators, or harmless archive layout.
3. Verify bytes and names after every transform and delayed processor. Poll with
   a bound; a pending or failed scan is not proof that content is safely rejected.
4. Test owner/peer read, replace, delete, and direct-storage retrieval with
   synthetic files. Never upload active HTML/script, malware, polyglots,
   decompression bombs, webshells, or other executable content by default.
5. Confirm retrieval content type, disposition, nosniff policy, randomized key,
   non-executable storage, and deletion of temporary/derived copies.

## Confirmation and evidence

Confirm a policy-relevant parser mismatch, root escape, unauthorized cross-tenant
operation, or reachability by an execution-capable consumer using inert content.
Save request, canary hash, all stage names/types/hashes, storage/retrieval path,
authorization matrix, worker state, negative control, and cleanup evidence.

## Remediation

Allowlist business-required types; validate extension, media type, and signature
together; generate storage names; canonicalize safely; cap size/count/archive
expansion; scan and transform in isolation; store outside executable/web roots;
serve through an authorization-checked handler with safe headers; separate
tenant namespaces; and delete temporary and derived artifacts reliably.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [File Upload](file-upload.md) — severity hint: critical
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
