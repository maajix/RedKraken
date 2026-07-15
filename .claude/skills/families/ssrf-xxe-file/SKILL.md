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
   Use synthetic internal fixtures by default. Cloud metadata, control-plane
   access, internal port scanning, credentials, and pivots are RoE-gated; never
   follow an OOB callback directly into them.
2. **XXE.** Inject a DTD with an external entity; in-band file read (`file:///etc/passwd`), else **blind/OOB** exfiltration via an external DTD on `oob_host`. Escalate XXE→SSRF, XXE→LFI, XXE→RCE (`expect://`, PHP filter) per the playbook.
3. **LFI / path traversal.** `../` + null/encoding bypasses; read source via `php://filter/convert.base64-encode`; **PHP filter chain → RCE** (no file upload needed); log/`/proc/self/environ` poisoning → RCE; wrappers (`data://`, `expect://`, `zip://`).
4. **File upload.** Bypass type/extension/content checks (double ext, magic bytes, `.phar`/`.phtml`, SVG/XML→XSS/XXE, polyglots) → drop a webshell, then locate & trigger it. RCE/webshell is destructive-adjacent — honor `destructive_allowed`; prefer proving write+exec minimally.

## Evidence
Capture the OOB callback log, the file contents read (`/etc/passwd`, source, metadata creds), or the webshell command output. Internal/metadata access is high impact — record the proof and stop pivoting unless intent + RoE cover it.
