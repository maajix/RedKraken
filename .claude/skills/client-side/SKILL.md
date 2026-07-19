---
name: client-side-attacks
description: Triage and exploit client-side & browser-trust flaws — XSS (reflected/stored/DOM), CSRF, CORS misconfig & XSSI, DOM vulnerabilities, prototype pollution (client & server), open redirect, dangling-markup/CSS exfiltration, tabnabbing, clickjacking, and WebSocket attacks. Use when input reflects into HTML/JS, or for cross-origin/browser-trust issues.
---

# Client-Side Family

Covers: **XSS** (reflected/stored/DOM), **CSRF**, **client-side path traversal**,
**CORS / XSSI**, **CSP/security-header/framing semantics**, **DOM vulnerabilities
and clobbering**, **browser storage/offline/client templates**,
**postMessage/workers**, **prototype pollution** (client &
server), **open redirect**, **dangling markup**, **tabnabbing**, **clickjacking**,
**WebSocket/WebTransport**, and **XS-Leaks**. Route through
`playbooks/_catalog.md` and read the matching topic `README.md` before its
imported depth notes. Obey `scope-guard` +
`tool-preflight`.

## Signals → technique

| Signal | Try |
|--------|-----|
| input reflected into HTML/JS/attribute | reflected/stored XSS |
| value flows into `innerHTML`/`eval`/`document.write`/sink in JS | DOM XSS |
| state-changing form/request without anti-CSRF token | CSRF |
| `Access-Control-Allow-Origin` reflects Origin / `*`+creds | CORS exfiltration; XSSI for JS data |
| `__proto__`/`constructor` accepted in JSON/query merge | prototype pollution → gadget (XSS/RCE) |
| `?redirect=`/`?next=`/`url=` | open redirect (→ oAuth token theft, phishing) |
| `target=_blank` without `noopener` | tabnabbing |
| page framable, sensitive actions | clickjacking |
| `ws://`/`wss://` channel | WebSocket hijack / message injection |
| `postMessage`, iframes, worker channels | origin/source confusion, privileged message dispatch |
| sanitized HTML with `id`/`name` | DOM clobbering → script/resource/worker gadget |
| query/fragment/route data builds a fetch path | client-side traversal → authenticated endpoint confusion |

## Approach

1. **XSS.** Load `playbooks/browser-script/README.md` first. Begin with inert text and
   trace the final parsed sink; use an isolated tester-owned browser and a local
   DOM/console marker. For stored paths use only tester-owned records and viewer
   identities, then clean up. Never collect cookies/tokens, beacon client data,
   or expose a real-user view.
2. **CSRF.** Confirm no token / token not validated / predictable; build a PoC HTML form that performs the state change cross-site.
3. **CORS / XSSI.** If ACAO reflects arbitrary Origin with `Allow-Credentials: true`, prove cross-origin read of authenticated data from an attacker page.
4. **Prototype pollution.** Pollute `__proto__.x` via JSON/query/merge; find a gadget that turns it into DOM XSS (client) or RCE/privesc (server, Node) per the playbook.
5. **Messaging / DOM clobbering / workers.** Verify `origin` and source-window
   identity, trace typed messages to privileged sinks, and test named DOM property
   collisions with benign canaries. Use an isolated browser profile and unregister
   every test service worker.
6. **Open redirect / dangling markup / tabnabbing / clickjacking / WebSockets.** Per-technique PoCs in the playbooks — chain open-redirect into OAuth/SSRF where intent allows.
7. **Client-side path traversal.** Load `playbooks/client-side-path-traversal/README.md`, trace the
   path source to its real request sink, and first redirect only to a read-only
   same-origin canary. Preserve the browser's actual method/body/credentials.
8. **Browser policy/framing.** Load `playbooks/browser-framing/README.md`; preserve raw
   duplicate headers, compute the effective route-specific policy, and validate
   sensitive framing only in an isolated tester-owned page with a benign control.
9. **Storage/offline/templates.** Load `playbooks/browser-storage/README.md`;
   trace one canary channel at a time, test two-account logout/switch cleanup and
   server-side authority, then clear storage, caches, and service workers.

## Evidence
Save the payload, the request, and proof of execution/exfiltration (screenshot/DOM, beacon hit on `oob_host`, cross-origin response read). Beacon to your own `oob_host` only — never to third-party collectors. Affecting other users (stored XSS firing broadly) is destructive-adjacent: prove with a scoped/test payload.
