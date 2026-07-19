---
id: modern-browser-storage-client-templates
title: Browser Storage, Offline State, and Client Templates
family: client-side
review_status: source-reviewed
reviewed_at: 2026-07-11
destructive_risk: medium
---

# Browser Storage, Offline State, and Client Templates

## Threat model

Trace data from URL, DOM, messages, API responses, local/session storage,
IndexedDB, Cache API, service workers, BroadcastChannel, clipboard, and extension
bridges into client templates, HTML/URL/script and CSS/style sinks, authorization
decisions, offline queues, synchronization, and cross-account state. Browser storage is
origin-scoped, not user- or tenant-scoped.

## Safe detection

1. In an isolated browser profile, inventory storage keys/databases/caches,
   producers, consumers, lifetime, sensitivity, user/tenant binding, logout
   cleanup, migration/version behavior, and offline-to-online synchronization.
2. Sign in as two tester accounts sequentially and verify logout/account/tenant
   switching clears or rebinds sensitive state, cached responses, drafts, queued
   actions, feature/role decisions, and service-worker caches.
3. Place a unique benign canary in one storage/input channel at a time and trace
   it into template compilation and DOM/URL/script sinks. Prefer a rendered text
   differential; use script execution only in the isolated tester page.
4. For CSS/style sinks, first prove only a harmless property/value change. Network
   fetches, attribute/value extraction, overlay/redress, and cross-user persistent
   styling are higher-impact proofs and remain explicitly gated.
5. Test stored state integrity with a non-privileged display preference first.
   Client-side role, entitlement, price, approval, or completed-state changes are
   confirmed only if the server accepts or acts on them.
6. Verify offline replay, duplicate queued actions, cache version upgrades, and
   worker activation with disposable data; unregister workers and clear all
   storage after the test.

## Confirmation and evidence

Confirm cross-account/tenant disclosure, persistent client-template execution,
server-trusted tampered state, or unauthorized replay from browser/offline state.
Save origin/profile, storage key and redacted value hash, source-to-sink trace,
two-account sequence, DOM/network/after-state evidence, worker/cache version,
negative control, and cleanup.

## Remediation

Keep secrets and authoritative security state server-side; namespace and bind
client state to account/tenant; clear it on logout/switch; use context-safe DOM
APIs and non-evaluating templates; validate/sanitize at the final sink; version
and purge caches safely; authorize every synchronized action server-side; and
protect offline queues with expiry, idempotency, and actor binding.

## Sources

- [OWASP WSTG: Testing Browser Storage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage)
- [OWASP WSTG: Testing for Client-side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/15-Testing_for_Client-Side_Template_Injection)
- [OWASP WSTG: Testing for CSS Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [WHATWG Web Storage](https://html.spec.whatwg.org/multipage/webstorage.html)
- [W3C Service Workers](https://www.w3.org/TR/service-workers/)
