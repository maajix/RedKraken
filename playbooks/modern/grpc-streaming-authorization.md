---
id: modern-grpc-streaming-authorization
title: gRPC Metadata and Streaming Authorization
family: access-control
review_status: source-reviewed
reviewed_at: 2026-07-10
destructive_risk: medium
---

# gRPC Metadata and Streaming Authorization

## Safe detection

1. Inventory services from supplied protobuf descriptors, application clients,
   and reflection only when the server intentionally exposes it.
2. Use grpcurl with explicit TLS and metadata against in-scope endpoints. Compare
   anonymous, peer, owner, cross-tenant, and privileged identities per method.
3. Test authorization for every message in client, server, and bidirectional
   streams, including identity expiry, logout, cancellation, and reconnect.
4. Vary protobuf fields one at a time: omitted vs default, unknown fields,
   `oneof`, enum boundaries, nested object IDs, and field masks.
5. Check that interceptors cover every service/method and that gateway-transcoded
   REST and native gRPC paths apply identical policy.
6. Inspect deadlines, message-size limits, backpressure, compression, and error
   detail with bounded requests. Do not flood streams.

## Confirmation and evidence

Save descriptor hashes, method, metadata names with values redacted, message
sequence, status/trailers, and authoritative state. Reflection exposure alone is
informational unless it reveals non-public services or enables another flaw.

## Remediation

Use TLS, validate bearer-token audience or mTLS identity, centralize interceptors
with deny-by-default method policy, authorize each stream message and object,
limit message sizes/concurrency, set deadlines, and avoid sensitive error detail.

## Sources

- [gRPC Authentication](https://grpc.io/docs/guides/auth/)
- [gRPC Metadata](https://grpc.io/docs/guides/metadata/)
- [gRPC Server Reflection](https://grpc.io/docs/guides/reflection/)
- [OWASP gRPC Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html)
