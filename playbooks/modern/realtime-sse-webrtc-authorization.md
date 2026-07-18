---
id: modern-realtime-sse-webrtc-authorization
title: SSE and WebRTC authorization lifecycle
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-18
destructive_risk: medium
---

# SSE and WebRTC authorization lifecycle

## Threat model

Long-lived EventSource streams and WebRTC signaling/media/data channels may authorize
only at setup, leak cross-tenant topics, reconnect with stale credentials, trust
client-supplied peer/session identifiers, expose private network candidates, or keep
delivering after logout, role change, revocation, or object transfer.

## Safe detection

1. Inventory SSE URLs/topics, signaling routes, ICE configuration, peer/session IDs,
   media tracks, and data-channel protocols using tester-owned identities.
2. Compare anonymous, owner, peer, and privileged subscription/setup attempts while
   changing only one identity, tenant, topic, object, or peer selector.
3. Revoke the session or permission during an active stream/call and observe delivery,
   reconnect, renegotiation, ICE restart, and new channel/track creation.
4. For SSE, test `Last-Event-ID`, redirect, cache, credential, and retry behavior with
   synthetic events. For WebRTC, use tester peers and benign data/media canaries;
   never connect to or record an unrelated peer.
5. Treat ICE candidates and logs as sensitive network metadata; redact addresses in
   orchestration context and retain only authorized evidence.

## Confirmation and evidence

Save the setup/subscription request, identity labels, topic or peer binding, synthetic
event/track marker, revocation timestamp, post-revocation behavior, and negative
control. Confirm only unauthorized delivery, peer/channel access, or persistence
beyond the documented authorization lifecycle.

## Remediation

Authorize every topic, peer, track, and data-channel capability server-side; bind
opaque session identifiers to actor and tenant; re-evaluate on reconnect/renegotiation;
terminate active delivery on revocation; use short-lived scoped TURN credentials;
minimize candidate/log exposure and disable caching for personalized streams.

## Sources

- [WHATWG Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [W3C WebRTC 1.0](https://www.w3.org/TR/webrtc/)
- [IETF RFC 8827 WebRTC Security Architecture](https://www.rfc-editor.org/rfc/rfc8827)
