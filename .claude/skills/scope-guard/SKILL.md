---
name: scope-guard
description: Mandatory scope + rules-of-engagement discipline for web pentesting. Use BEFORE running any networked tool or request against a target, and whenever a target/intent is ambiguous. Enforces deny-by-default scope, destructive-action gating, rate limits, and audit logging.
---

# Scope Guard

Non-negotiable rules for every action in an engagement. Violating scope is the one unrecoverable mistake — treat it as a hard stop, not a judgment call.

## Before touching ANY host

1. Resolve the engagement dir (env `PENTEST_ENGAGEMENT_DIR`, set by the command). It contains `engagement.yaml`.
   Start every engagement shell with `umask 077`; run
   `python3 "$HARNESS/lib/secure_engagement.py" "$PENTEST_ENGAGEMENT_DIR"`
   at phase boundaries and before reporting.
2. Scope-check the exact host/URL:
   ```bash
   bash "$HARNESS/lib/scope_check.sh" "<url-or-host>"   # exit 0 = IN, 1 = OUT
   ```
   - **OUT_OF_SCOPE → do not run the command.** Record a one-line note and move on. Never "just check quickly".
   - The `PreToolUse` hook also blocks out-of-scope commands, but you must check explicitly too — defense in depth, and the hook can't reason about intent.
3. The checker fails **closed**: if it errors or no engagement is loaded, treat everything as out of scope and stop to fix setup.

## Ambiguity → STOP and ask the operator

If the target list or the `intent` is missing, empty, contradictory, or you are unsure whether something is authorized:
> Stop the loop and ask the user to clarify target and intent. Do not guess. Do not proceed on a "probably fine".

## Rules of engagement (from `engagement.yaml`)

- Resolve the independent RoE gates with `harness_config.roe_authorizations`:
  `mutation_allowed`, `sensitive_data_access_allowed`,
  `credential_use_allowed`, `pivoting_allowed`, and
  `availability_impact_allowed`. Missing gates fail closed. An action must satisfy
  every gate it needs; no gate overrides target scope. `destructive_allowed` is a
  legacy fallback for mutation only.
- When a required gate is false, use the least-sensitive, non-mutating synthetic
  proof or record `status: exploitable-not-detonated`. Never include a live secret
  in a proposed command or finding.
- **Rate limiting is opt-in.** If and only if `rate_limit_enabled: true`, the
  shared proxy token bucket enforces `rate_limit` across target-hitting HTTP tools;
  do not hand-throttle them again. Direct passive/DNS tools self-throttle with a
  native RPS flag, or one worker plus a delay of at least `1 / rps`. `per_tool`
  overrides may only tighten the global limits.
- **`required_headers`** → the proxy injects every configured entry into every
  in-scope HTTP request. A target HTTP tool that cannot use the proxy is
  `not-tested`; never fall back to direct traffic.
- **`max_threads`** is a legacy concurrency hint, not permission for high load.
- **`time_window`** → if set and now is outside it, stop.
- Respect `out_of_scope` even for OOB/callback hosts; use `oob_host` from the config for blind callbacks.

## Shared scope proxy liveness

Exactly ONE scope proxy runs per host at `127.0.0.1:18080`. It is the sole
sanctioned egress: it injects `required_headers` (e.g. `X-Bug-Bounty`) and enforces
the rate policy, so **traffic that skips it carries neither** and is an RoE
violation even when the target is in scope.

- **Check liveness passively:** `python3 lib/proxy_supervisor.py health
  "$PENTEST_ENGAGEMENT_DIR"`. It reads the supervisor owner lock (with recent
  proxy activity as fallback), so an idle proxy remains healthy and no sandbox or
  network namespace can hide it. Never curl `127.0.0.1:18080` as a health probe.
- **Route proxied traffic with the sandbox DISABLED — every networked call, not
  just the probe.** Claude Code's Bash sandbox has an empty network allowlist and
  **no host:port/loopback allowance**, so a sandboxed command cannot reach
  `127.0.0.1:18080` (`ERR_PROXY_CONNECTION_FAILED`). Run any command that reaches
  the proxy with `dangerouslyDisableSandbox: true`.
- Run target HTTP tools as **`./scripts/run_scoped_http.sh <tool> ...`**. This tiny,
  reviewed runner sets every HTTP/HTTPS proxy variant and clears inherited
  `NO_PROXY`; that keeps curl's HTTPS→HTTP redirects inside the proxy too. It is
  also a transparent scope-hook prefix: the real tool and literal targets remain
  statically inspectable. A prior `export`, bare proxy env, or `curl -x` is denied.
- **The scope-guard hook now hard-DENIES any in-scope HTTP-egress tool**
  (curl/wget/httpx/nuclei/ffuf/gobuster/feroxbuster/dirb/dirsearch/katana/
  gospider/hakrawler/wfuzz/wpscan/dalfox/sqlmap/arjun/schemathesis/x8/whatweb/
  wafw00f) **that is not routed through the reviewed runner.** DNS/passive/
  transport tools (subfinder/dnsx/amass/gau/waybackurls/nmap/
  openssl/nc…) are exempt (they don't use the HTTP proxy).
- **Restart is ORCHESTRATOR-ONLY.** The proxy is a process and can die mid-run (a
  crash, or the OOM-killer reaping `mitmdump` and its supervisor). If you are a
  **sub-agent** and the passive health command reports unhealthy: **HALT and
  REPORT — never restart it yourself** (concurrent restarts fight over the port).
  The **orchestrator** restarts with `bash scripts/start_scope_proxy.sh
  <engagement-dir>` (idempotent: no-ops if already healthy; refuses to start over a
  foreign process) and re-dispatches. Verify liveness immediately before each
  networked dispatch — not just once at startup.
- **Never launch a second proxy, and never kill/replace a live one to "reset" it.**

## Agent-created files

- Network-capable helpers must be reviewed root `scripts/` entry points; never
  hide targets inside an engagement-local Python/Node/shell driver. Use the
  scoped runner, literal arguments, or an inspectable tool input file such as
  `curl -K`.
- Put reusable, offline engagement transforms in `state/scripts/`, disposable
  experiments in `state/scratch/`, and raw tool output only in `state/scan-raw/`.
  See `scripts/README.md` before promoting a helper for all engagements.

## Audit every executed command

Claude Code `PostToolUse`/`PostToolUseFailure` hooks automatically write redacted
structured events and result hashes to `audit.jsonl`. For commands executed outside
Claude Code, record them explicitly:
```bash
bash "$HARNESS/lib/audit.sh" "<phase-or-family>" "<the exact command>"
```
The structured audit stream is part of the client deliverable. No unaudited target traffic.

`$HARNESS` = repo root (the dir containing `lib/` and `playbooks/`).
