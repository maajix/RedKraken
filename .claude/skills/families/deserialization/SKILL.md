---
name: deserialization-attacks
description: Triage and exploit insecure deserialization in PHP, Python (pickle), Java, and .NET — identify serialized blobs in params/cookies/uploads and build gadget-chain payloads toward RCE. Use when you see serialized objects (PHP O:/a:, Python pickle, Java rO0/ac ed, .NET) in untrusted input.
---

# Deserialization Family

Covers: **PHP**, **Python (pickle/PyYAML)**, **Java**, **.NET**, native object
streams, YAML/XML, polymorphic JSON, and other type-reconstructing formats. Start
with `playbooks/modern/untrusted-data-deserialization.md`, then open the precise
imported playbook via `playbooks/web/_catalog.md`. Obey `scope-guard` +
`tool-preflight`.

## Signals → format

| Signal in input (param/cookie/header/upload) | Format |
|----|----|
| `O:8:"...":` / `a:2:{...}` | PHP `serialize()` |
| base64 starting `gASV` / `\x80\x04` / uses `pickle`,`PyYAML`,`jsonpickle` | Python pickle/yaml |
| base64 starting `rO0AB` / bytes `AC ED 00 05` | Java |
| `AAEAAAD/////` / `TypeObject`, ViewState | .NET / ViewState |

## Approach

1. **Identify & decode** the blob; map the language/framework from the recon tech tags.
2. **Find a gadget chain.**
   - PHP: hunt POP chains in the app's classes (`__wakeup`/`__destruct`/`__toString`), or `phpggc` for known frameworks (Laravel, Symfony, Monolog…).
   - Python: `pickle`/`__reduce__` → direct code exec; PyYAML `!!python/object/apply`.
   - Java: `ysoserial` (CommonsCollections, etc.); identify libs on the classpath (often via recon/error leaks, decompiling JARs).
   - .NET: `ysoserial.net`; ViewState without MAC (machineKey).
3. **Confirm safely** with an inert canary in a local/disposable process or an
   unauthorized-type/hook effect that performs no file, command, network, or
   availability action. OOB and command gadgets are exploitation and require the
   corresponding RoE gate; they are not the default proof.

## Evidence
Save the serialized artifact/hash, decoded structure, delivery request,
source-to-sink path, reachable type/hook, filter decision, inert canary effect,
runtime/library version, negative control, and cleanup. Deserialization-to-RCE is
destructive-adjacent; stop at the minimal inert proof unless explicitly allowed.
