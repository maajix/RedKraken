---
id: modern-server-file-resolution-boundaries
title: Server File Resolution Boundaries
family: ssrf-xxe-file
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: high
---

# Server File Resolution Boundaries

## Threat model

Trace untrusted filenames and paths through decoding, Unicode handling,
separator normalization, symlink resolution, archive or virtual filesystems,
framework includes, wrappers, and final read/write/include operations. A lexical
prefix check can disagree with the filesystem's canonical target.

## Safe detection

1. Inventory path inputs in parameters, headers, cookies, manifests, archives,
   templates, exports, and background jobs. Record every decode/normalize step.
2. Create an inert uniquely named file inside an authorized synthetic fixture,
   plus an allowed control. Change one traversal, absolute-path, separator,
   encoding, Unicode, extension, wrapper, or archive-boundary property at a time.
3. Compare the application-selected canonical path and returned hash/content.
   Do not read operating-system, cloud, credential, source, or other-tenant files
   for default confirmation.
4. Test symlink and archive extraction behavior only in tester-owned storage.
   Clean up links, files, and extracted trees after recording authoritative
   after-state.
5. Remote inclusion, log poisoning, filter-chain execution, file writes, and RCE
   are separate escalation steps requiring explicit RoE authorization.

## Confirmation and evidence

Confirm when the resolved target escapes the intended root or selects a
synthetic file that policy should deny. Save raw input, every normalized form,
canonical target, operation type, response/file hash, negative control,
filesystem/version context, and cleanup proof.

## Remediation

Map opaque identifiers to server-owned files; canonicalize once with the same
filesystem semantics used for access; verify the canonical target is beneath an
allowlisted root; reject absolute paths, unexpected schemes, links, and archive
escapes; separate upload/read/include roots; use least privilege; and open files
with race-resistant APIs where available.

## Sources

- [OWASP WSTG: Testing Directory Traversal File Include](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [OWASP WSTG: Testing for File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
