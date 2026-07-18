---
id: modern-command-directory-entity-injection
title: Command, directory, and external-entity injection
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: high
---

# Command, directory, and external-entity injection

## Threat model

Untrusted data becomes control syntax when applications construct operating-system
commands or arguments, LDAP distinguished names or filters, or XML documents parsed
with external entities and dangerous features enabled. Quoting, escaping, platform
differences, nested interpreters, delayed jobs, and parser configuration can make an
apparently data-only value executable or able to alter a directory query or resolve
an unintended external resource.

## Safe detection

1. Identify the exact sink, platform, parser/library, data context, construction API,
   and delayed consumers. Prefer source/configuration evidence and controlled test
   fixtures before sending syntax-changing input.
2. For command/argument boundaries, use a harness-owned command fixture that returns
   a literal canary. Vary one separator, quote, option boundary, or argument at a
   time; do not create files, start processes, access environment data, or use
   outbound callbacks on a production host.
3. For LDAP, use a synthetic directory record and paired filters that differ only in
   one escaped metacharacter, attribute, or boolean clause. Never enumerate or
   modify real directory entries and do not attempt authentication as another user.
4. For XML, use a minimal document and a harness-owned local resource or callback to
   determine whether DTD/external resolution is enabled. Do not read system files,
   cloud metadata, internal services, or use recursive/general-entity expansion
   unless separately authorized for a bounded proof.
5. Require a literal/boolean/resolution negative control. Timing, errors, blocked
   callbacks, or reflection without interpreter behavior remain leads.

## Confirmation and evidence

Save the minimized input, exact sink and context, parser/runtime version, literal
command-fixture output or directory true/false result or owned entity-resolution
event, matched negative control, after-state, and cleanup. Confirm only deterministic
control over command/argument interpretation, LDAP query meaning, or external entity
resolution—not an error message alone.

## Remediation

Avoid command interpreters and pass fixed executables with separated allowlisted
arguments; use LDAP APIs with context-appropriate filter/DN escaping and fixed query
structure; disable DTDs, external entities, XInclude, and network access in XML
processors. Run consumers with least privilege and add regression cases for each
parser and delayed path.

## Sources

- [OWASP WSTG v4.2: Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [OWASP WSTG v4.2: Testing for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
