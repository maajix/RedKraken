---
id: modern-untrusted-data-deserialization
title: Untrusted Data Deserialization and Type Reconstruction
family: deserialization
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: high
---

# Untrusted Data Deserialization and Type Reconstruction

## Threat model

Trace cookies, tokens, queues, caches, files, RPC messages, view state, session
state, model/config artifacts, and inter-service data into any mechanism that
reconstructs types or invokes hooks. Include native object streams, YAML/XML,
polymorphic JSON, binary formats, signed-but-readable blobs, and integrity checks
performed by a different parser than deserialization.

## Safe detection

1. Identify format, producer, consumer, type metadata, integrity/encryption,
   allowlist/filter, library/runtime version, and reachable classes or callbacks.
   Decode only tester-owned artifacts and preserve an untouched control.
2. Change one structural property at a time: benign unknown type, extra field,
   type mismatch, duplicate field, nesting, invalid signature, or harmless class
   that has an observable non-dangerous validation effect. A parse error is a lead.
3. In source, trace untrusted bytes through verification to the exact
   deserializer and reachable hooks (`readObject`, `__reduce__`, constructors,
   setters, converters, finalizers, magic methods). Confirm allowlists/filters
   apply before object creation and at every nested type.
4. Use a local disposable process and an inert canary callback to validate a
   suspected gadget path. Do not deliver command, file, network, or denial-of-
   service gadgets to a live service by default.
5. Test signing/encryption binding with tester keys: wrong purpose, tenant,
   environment, type, algorithm, or stale/revoked key must fail before decoding.

## Confirmation and evidence

Confirm when untrusted input instantiates an unauthorized type or invokes a
security-relevant hook, or when a type/integrity boundary is bypassed, using an
inert local or isolated canary. RCE gadget execution is not required and remains
explicitly gated. Save format bytes/hash, decoded structure, source-to-sink path,
runtime/library versions, filter decision, canary effect, negative control, and
cleanup.

## Remediation

Do not deserialize native object graphs from untrusted data. Use simple typed
schemas, strict allowlists and size/depth limits, safe parser modes, integrity
bound to type/purpose/tenant/environment, filters before construction, isolated
workers with least privilege, maintained libraries, and migration away from
legacy formats. Signing unsafe serialized objects does not make gadget-rich
decoding safe if keys or purpose boundaries fail.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [Deserialization Attacks](deserialization-attacks.md) — severity hint: critical
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python documentation: pickle warning](https://docs.python.org/3/library/pickle.html)
- [Java Serialization Filtering](https://docs.oracle.com/en/java/javase/24/core/serialization-filtering1.html)
