---
id: modern-ssti-error-oracles
title: Error-Based and Boolean-Blind Template Injection
family: injection
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Error-Based and Boolean-Blind Template Injection

## Safe detection

1. Locate values that may be compiled as template source rather than passed as
   data: previews, mail/document templates, CMS themes, labels, localization,
   notification rules, and server-side rendering helpers.
2. Establish stable normal and malformed-input controls. Test harmless arithmetic
   or syntax fingerprints for the suspected engine, including contexts where the
   response does not render expression output.
3. Add error-based checks: compare an expression that succeeds with one that
   deterministically fails. Observe status, headers, body shape, redirects, and
   server timing; do not assume that every `500` came from template evaluation.
4. For boolean error-based blind behavior, encode a known true/false condition
   over a synthetic in-template canary. Repeat paired controls and minimize the
   expression before attempting any read.
5. Prefer one-character synthetic proof. Filesystem, environment, secret, or
   command access is exploitation and requires the exploit-agent and RoE gate.
   Avoid payloads that allocate heavily, recurse, or sleep repeatedly.

## Confirmation and evidence

Confirm with a repeatable engine-specific evaluation or true/false error oracle
that reveals the synthetic canary. Save the input context, engine/version evidence,
successful and failing pairs, response dimensions, trial count, logs if available,
and the minimal expression. A generic error or timing change remains suspected.

## Remediation

Never concatenate untrusted data into template source; use fixed templates and
data-only bindings. Treat sandboxing as defense in depth, minimize exposed objects
and functions, disable dynamic template features where possible, patch the engine,
and return uniform external errors while preserving internal diagnostics.

## Sources

- [Successful Errors: New Code Injection and SSTI Techniques](https://2025.offzone.moscow/eng/program/successful-errors-new-code-injection-and-ssti-techniques/)
- [SSTImap](https://github.com/vladko312/SSTImap)
- [PortSwigger Server-Side Template Injection research](https://portswigger.net/research/server-side-template-injection)
- [OWASP WSTG: Testing for Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)

