---
name: web-recon
description: Web application reconnaissance & attack-surface mapping methodology — enumerate hosts, endpoints, parameters, and tech stack within scope, then persist a structured target map. Use during the recon phase of a web pentest, before vulnerability hunting.
---

# Web Recon & Mapping

Goal: produce a structured, scope-clean map of the attack surface in `state/endpoints.json` and `state/targets.json` that triage can route to attack families. Obey `scope-guard` and `tool-preflight` for every command. Apply tool rate/concurrency options only when `rate_limit_enabled: true` in `engagement.yaml`.

## Bounded iterative closure

Treat every in-scope host, endpoint, schema, parameter, identity-dependent route,
and technology signal as an observation. Persist actionable hypotheses through
`python3 scripts/lead_state.py`; do not use `notes.md` as a lead tracker. After each
round, compute the **surface delta** from stable normalized target/endpoint
fingerprints. New schemas, routes, roles, virtual hosts, client bundles, and API
relationships seed a targeted next round.

Use an explicit **round budget** and request/time constraints from the run policy.
Stop after **two no-progress rounds**, budget exhaustion, or an operator-required
gate. A parse/tool failure is not progress. Update the **coverage ledger** for each
recon method with `tested`, `exhausted`, `blocked`, `not-applicable`, or
`not-tested` and an evidence/reason reference.

## Order of work

1. **Resolve hosts.** For each in-scope domain: `subfinder -d <d> -silent` (+ `amass enum -passive` if time allows) → `dnsx -silent -a` to resolve. Keep only in-scope results (scope-check each).
2. **Probe live web.** `httpx -l hosts.txt -silent -td -title -sc -server -ip -json` → captures status, title, tech, server, redirects. This is the backbone of `targets.json`.
3. **Fingerprint.** `scripts/run_whatweb.sh -a3 <url>` and the httpx `-td` tech tags. Detect CMS (WordPress/Joomla/Drupal), frameworks, languages, WAF (`wafw00f <url>`). The wrapper isolates WhatWeb from incompatible user-installed Ruby gems. Tech tags drive family triage (PHP→LFI/deser, Node→prototype-pollution, Java→deser/SSTI, etc.).
4. **Content discovery.** `feroxbuster -u <url> --rate-limit <rl> -q` (or `ffuf -u <url>/FUZZ -w <wordlist> -rate <rl>`). Look for admin panels, APIs, backups, `.git`, dev endpoints, status-code anomalies.
   For IP-routed or default-host surfaces use
   `scripts/run_vhost_discovery.sh`; it expands and scope-checks every concrete
   Host before ffuf, uses multiple random controls, confirms anomalies, and
   records logical host separately from route IP. Build a bounded second-pass
   list only from saved in-scope artifacts with `scripts/build_recon_wordlist.py`.
5. **Historical + crawl.** `gau <host>` / `waybackurls <host>` for known URLs; `katana -u <url> -jc -silent` to crawl live. Merge, dedupe, scope-filter.
6. **Parameter mining.** `paramspider -d <domain>` and extract params from crawled URLs / forms / JS. Parameters are where most injection bugs live — capture name + location (query/body/header/cookie/path).
7. **Quick wins.** A light `nuclei -u <url> -severity low,medium,high,critical -rl <rl>` pass surfaces known CVEs/misconfigs cheaply. Treat hits as *leads to verify*, not confirmed findings.

## Auth-aware recon

If `test_credentials` are provided: log in, capture the session cookie/token, and re-crawl authenticated areas (often a much larger surface). Note auth mechanism (session cookie / JWT / SAML / oAuth) — it directly seeds the `auth-session` family.

For an SPA or browser-only flow, start the enforcement proxy and capture a clean
per-role context rather than importing a personal browser profile:
```bash
bash scripts/start_scope_proxy.sh "$PENTEST_ENGAGEMENT_DIR" 18080 playwright
bash scripts/browser_capture.sh "$PENTEST_ENGAGEMENT_DIR" "<in-scope-url>" "<role>" --proxy http://127.0.0.1:18080
```
Run the proxy in a separate terminal/process. Its per-request scope and optional
rate policy are stronger than the CLI hook.

## Output schemas (write with `jq`/python, keep valid)

`state/targets.json` — array of:
```json
{"url":"https://app.x.com","status":200,"title":"...","tech":["PHP","nginx"],"waf":"cloudflare","cms":null}
```
`state/endpoints.json` — array of:
```json
{"url":"https://app.x.com/item","method":"GET","params":[{"name":"id","in":"query"}],
 "tech":["PHP"],"auth":"cookie","notes":"reflects id in page"}
```

Keep everything scope-filtered and return the total surface, per-round surface delta,
notable tech/WAF/CMS, derived leads, and explicit coverage gaps for triage.

## Raw-output contract

- Preserve full scanner output under `state/scan-raw/` with directory `0700` and
  files `0600`; cap stdout or write directly there before reading it.
- Return only structured counts, hashes, redacted high-signal slices, and evidence
  paths. Never inline raw credentials, cookies, tokens, personal data, or full
  client responses into model/orchestration context.
- Truncation must never destroy the only evidence copy. Parse/truncation/tool
  failures are `not-tested` coverage, never successful coverage.
