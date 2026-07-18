---
name: ssrf-xxe-file
description: Triage and exploit server-side resource & file attacks — SSRF (incl. filter bypasses & DNS rebinding), XXE (incl. blind/OOB and XXE→LFI/RCE), LFI/path traversal (incl. PHP filter-chain → RCE and log poisoning), file upload → webshell, and SSRF/LFI via PDF generators. Use when a param takes a URL, file path, filename, XML, or upload.
---

# SSRF / XXE / File Family

Covers: **SSRF** (+ filter bypasses, DNS rebinding), **XXE** (+ blind/OOB, XXE→LFI/RCE), **LFI / path traversal** (+ PHP filter chain→RCE, log poisoning, wrappers), **File Upload** (+ bypass→webshell), **PDF generators** (HTML/SSRF/LFI). Open the precise playbook via `playbooks/web/_catalog.md`. Obey `scope-guard` + `tool-preflight`.

## Signals → technique

| Signal | Try |
|--------|-----|
| param is a URL / fetches remote content / webhook / preview | SSRF |
| `Content-Type: */xml`, SOAP, SAML, file import | XXE |
| param is a filename/path / `?page=`/`?file=`/`include` | LFI / path traversal |
| upload form / avatar / document import | file upload → webshell |
| server renders HTML→PDF/image | PDF generator SSRF/LFI via injected HTML |

## Approach

1. **SSRF.** Load `playbooks/modern/url-parser-ssrf-routing.md`. Confirm first
   against `oob_host`, record the actual connected destination, and test parser
   edge classes, redirects, DNS, and address normalization one variable at a time.
   Use synthetic internal fixtures by default. Reading cloud metadata requires
   `sensitive_data_access_allowed`; using returned credentials separately
   requires `credential_use_allowed`; following the path to another in-scope
   service requires `pivoting_allowed`. Never follow an OOB callback directly
   into any of them.
2. **XXE.** Use an inert local or approved OOB canary first. External file reads,
   internal service access, recursive expansion, and RCE are escalation-gated.
   Real system/source data requires `sensitive_data_access_allowed`; resource
   exhaustion also requires `availability_impact_allowed`.
3. **LFI / path traversal.** Load `server-file-resolution-boundaries.md`; prove
   canonical-root escape only with a uniquely named synthetic file. System,
   source, credential, wrapper/filter-chain, log-poisoning, write, and RCE paths
   require explicit RoE escalation. `/etc/passwd` is a non-destructive read, but
   it is still real system data and requires `sensitive_data_access_allowed`.
4. **File upload.** Load `file-upload-processing-boundaries.md`; map upload →
   transform → scan → store → retrieve with inert canaries and owner/peer
   fixtures. Active HTML/script, malware, polyglots, archive bombs, webshells,
   and execution are never default detection. Target writes or execution require
   `mutation_allowed`; archive bombs require `availability_impact_allowed`.

`destructive_allowed` is a legacy fallback for `mutation_allowed` only. It does
not grant `sensitive_data_access_allowed`, `credential_use_allowed`,
`pivoting_allowed`, or `availability_impact_allowed`.

## Evidence
Capture the least-sensitive decisive proof: an OOB callback, synthetic canary,
redacted authorized read, or command identity. Never store a live credential in
the finding. Stop before mutation, sensitive access, credential use, pivoting,
or availability impact unless every corresponding gate and scope check passes.
