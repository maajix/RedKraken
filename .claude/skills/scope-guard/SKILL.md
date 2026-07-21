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
- **Rate limiting is opt-in.** If and only if `rate_limit_enabled: true`, enforce
  `rate_limit` through `scripts/start_scope_proxy.sh` for browser/schema wrappers
  and compatible native flags for direct CLI tools. Direct rate-limited work is
  serialized; a tool without a reliable RPS flag uses one worker plus a delay of
  at least `1 / rps` seconds. `per_tool` overrides may only tighten the global
  RPS/burst/concurrency limits. When the switch is absent or false, do not
  silently apply the example values.
- **`required_headers`** → apply every configured entry to every in-scope HTTP
  request. The scope proxy injects them for proxied browser/schema workflows.
  Direct CLI tools must use their tool-native header option; if a tool cannot
  apply all mandatory headers, do not send the request and record `not-tested`.
- **`max_threads`** is a legacy concurrency hint, not permission for high load.
- **`time_window`** → if set and now is outside it, stop.
- Respect `out_of_scope` even for OOB/callback hosts; use `oob_host` from the config for blind callbacks.

## Shared scope proxy liveness

Exactly ONE scope proxy runs per host at `127.0.0.1:18080`. Before relying on it,
and whenever a run reports it "down":

- **Check liveness with the sandbox DISABLED.** An in-sandbox loopback probe
  cannot see an out-of-sandbox listener, so it reports a false "down" — which used
  to trigger a spurious restart that then crashed on `address already in use`.
- **(Re)start with `bash scripts/start_scope_proxy.sh <engagement-dir>`.** It is
  idempotent: if a healthy proxy is already listening it no-ops, so a redundant
  start can no longer kill the running proxy. It refuses to start over a foreign
  process holding the port instead of fighting it.
- **Never launch a second proxy, and never kill/replace a live one to "reset" it.**

## Audit every executed command

Claude Code `PostToolUse`/`PostToolUseFailure` hooks automatically write redacted
structured events and result hashes to `audit.jsonl`. For commands executed outside
Claude Code, record them explicitly:
```bash
bash "$HARNESS/lib/audit.sh" "<phase-or-family>" "<the exact command>"
```
The structured audit stream is part of the client deliverable. No unaudited target traffic.

`$HARNESS` = repo root (the dir containing `lib/` and `playbooks/`).
