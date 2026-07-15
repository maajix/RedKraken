---
description: Run only the recon / attack-surface mapping phase for an engagement.
argument-hint: <engagement-dir>  e.g. engagements/acme
---

Run reconnaissance only for engagement: **$ARGUMENTS**

1. Require `$ARGUMENTS/engagement.yaml`. If `targets` empty or `intent` missing/ambiguous → stop and ask the operator (scope-guard).
2. Initialize or verify with `python3 lib/run_context.py "$ARGUMENTS" --mode recon`; stale context is a hard stop. Run `bash lib/preflight.sh` and report tool gaps.
3. Dispatch the **`recon-agent`** (Task tool) with the engagement dir. Let it follow the `web-recon` skill and write `state/targets.json` + `state/endpoints.json`.
4. Report its summary (surface size, tech/CMS/WAF, promising endpoints per family). Do not proceed to hunting — this command is recon only.
