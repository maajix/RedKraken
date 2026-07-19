---
id: modern-spreadsheet-formula-injection
title: CSV and Spreadsheet Formula Injection
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# CSV and Spreadsheet Formula Injection

## Threat model

Trace untrusted values from forms, imports, integrations, databases, and formulas
into CSV/XLSX/ODS generation and every spreadsheet application expected to open
the export. Quoting is a data-format rule, not necessarily a formula-safety rule.

## Safe detection

1. Create a disposable record containing benign literal markers beginning with
   formula-trigger characters, including leading whitespace/control variants
   supported by the intended spreadsheet clients.
2. Export through each role, locale, delimiter, encoding, and file format. Inspect
   the raw CSV or workbook XML first and record the exact cell type/value.
3. If authorization permits opening the file, use an isolated offline profile and
   a local arithmetic-only formula canary. Do not use DDE, commands, files, URLs,
   macros, external data, or network callbacks.
4. Test whether sanitization survives quote removal, copy/paste, import/export
   round trips, and generated formulas while preserving legitimate literal data.
5. Check headers, filenames, sheet names, and metadata separately; do not assume
   cell-value protection covers workbook structure.

## Confirmation and evidence

Confirm only when an operator-controlled value becomes a formula in a supported
client or the serialized cell is explicitly formula-typed. Save source value,
raw exported bytes/XML, client/version and locale, rendered result screenshot,
negative control, and deletion of the disposable record/file.

## Remediation

Use a spreadsheet-aware writer with explicit string cell types; neutralize all
formula-leading characters after canonicalization; preserve literal values;
avoid generating formulas from untrusted input; warn on risky exports; and test
every supported format/client/locale with regression fixtures.

## Sources

- [OWASP WSTG: Testing for CSV Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_CSV_Injection)
- [CWE-1236: Improper Neutralization of Formula Elements in a CSV File](https://cwe.mitre.org/data/definitions/1236.html)
