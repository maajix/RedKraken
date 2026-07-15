# Modern Web Attack Catalog

Source-reviewed supplements for attack surfaces that are underrepresented in the
imported note library. Read these before the broader `playbooks/web/` entry when
the signal matches. Detection is deliberately non-destructive by default.

| signal | family | playbook | reviewed |
|---|---|---|---|
| OAuth/OIDC authorization or token endpoints | auth-session | `oauth-security-bcp.md` | 2026-07-11 |
| login, MFA, recovery, remembered devices, sensitive-action reauthentication | auth-session | `authentication-mfa-recovery-lifecycle.md` | 2026-07-11 |
| passkeys, FIDO2, WebAuthn ceremonies | auth-session | `webauthn-passkeys.md` | 2026-07-10 |
| ambiguous/duplicate cookies or cookie prefixes | auth-session | `cookie-parser-differentials.md` | 2026-07-11 |
| SAML or email-derived identity/tenant decisions | auth-session | `identity-parser-differentials.md` | 2026-07-11 |
| OpenAPI, multi-step REST, business workflows | access-control | `api-stateful-business-logic.md` | 2026-07-10 |
| framework data/action/prefetch routes or internal routing headers | access-control | `framework-routing-trust-boundaries.md` | 2026-07-11 |
| inbound signed events, retries, asynchronous consumers | access-control | `webhook-event-authenticity.md` | 2026-07-11 |
| errors, cancellation, dependency or queue partial failures | access-control | `exceptional-condition-security.md` | 2026-07-11 |
| concurrent state changes, single-use actions, hidden sub-states | access-control | `race-conditions-state-machines.md` | 2026-07-11 |
| user-controlled ORM filters, relations, query shape | access-control | `orm-relational-filter-leaks.md` | 2026-07-11 |
| GraphQL queries, mutations, subscriptions | access-control | `graphql-authorization-cost.md` | 2026-07-10 |
| gRPC, protobuf, server/client streaming | access-control | `grpc-streaming-authorization.md` | 2026-07-10 |
| multiple HTTP parsers, upstream HTTP/1.1, downgrade/coalescing | http-protocol | `http2-desync.md` | 2026-07-11 |
| CDN/cache plus dynamic authenticated content | http-protocol | `web-cache-normalization.md` | 2026-07-10 |
| server-side URL fetch, redirect, callback, webhook | ssrf-xxe-file | `url-parser-ssrf-routing.md` | 2026-07-11 |
| WebSocket, WebTransport, cross-site state oracle | client-side | `browser-realtime-xsleaks.md` | 2026-07-10 |
| postMessage, frames, workers, sanitized HTML | client-side | `browser-messaging-dom-clobbering.md` | 2026-07-11 |
| CSP/security headers, sensitive framing, cross-origin browser policy | client-side | `browser-policy-framing.md` | 2026-07-11 |
| local/session storage, IndexedDB, caches, offline queues, client templates | client-side | `browser-storage-client-templates.md` | 2026-07-11 |
| browser-built request path from query/fragment/route/API data | client-side | `client-side-path-traversal.md` | 2026-07-11 |
| template compilation, blind/error-only rendering | injection | `ssti-error-oracles.md` | 2026-07-11 |
| JSON/filter type changes, NoSQL operators, query-shape objects | injection | `nosql-operator-injection.md` | 2026-07-11 |
| CSV/XLSX/ODS exports containing untrusted cells | injection | `spreadsheet-formula-injection.md` | 2026-07-11 |
| XML/XSLT, expressions, SSI/ESI, format strings, delayed interpreter sinks | injection | `structured-interpreter-injection.md` | 2026-07-11 |
| LLM, RAG, agent tools, MCP client/server | agentic-ai | `agentic-mcp-trust-boundaries.md` | 2026-07-10 |
| secret/key/token material, crypto or randomness, sensitive data protection | secrets-crypto | `secrets-cryptographic-controls.md` | 2026-07-11 |
| dependencies, CI/CD, builds, registries, updates, artifact provenance | supply-chain | `software-supply-chain-integrity.md` | 2026-07-11 |
| cloud/container/IaC, admin/debug exposure, deployed-policy drift | config-iac | `deployment-configuration-exposure.md` | 2026-07-11 |
| API versions/inventory, expensive operations, third-party API trust | config-iac | `api-inventory-resource-consumption.md` | 2026-07-11 |
| security events, audit records, alert delivery, telemetry failure | config-iac | `security-logging-alerting.md` | 2026-07-11 |
| stack traces, source maps, backups, debug/build artifacts, metadata leakage | config-iac | `information-disclosure-debug-artifacts.md` | 2026-07-11 |
| native objects, polymorphic data, signed blobs, queues/caches/session state | deserialization | `untrusted-data-deserialization.md` | 2026-07-11 |
| CMS core, plugins/modules/themes, roles/content, install/update surfaces | cms | `cms-extension-platform-boundaries.md` | 2026-07-11 |
| SCIM/JIT, invitations, groups/roles, suspension/deletion, identity reuse | access-control | `identity-provisioning-role-lifecycle.md` | 2026-07-11 |

Every card records its primary standards or project sources. Re-review a card
when its cited draft/specification changes or before turning a safe differential
check into a cross-user or state-changing proof.
