---
description: (Re)generate the penetration-test report from an engagement's findings.
argument-hint: <engagement-dir>  e.g. engagements/acme
---

Generate the report for engagement: **$ARGUMENTS**

1. Require `$ARGUMENTS/state/findings.jsonl`. If it's missing/empty, tell the operator there are no findings yet (run `/pentest` first).
2. Verify the immutable run context: `python3 lib/run_context.py "$ARGUMENTS" --mode report`. A stale context is a hard stop until prior state is archived.
3. Render deterministically: `python3 scripts/render_report.py "$ARGUMENTS"`.
4. Optionally dispatch the **`reporter`** read-only to flag unclear wording or missing data, but do not let it rewrite finding facts or evidence hashes.
5. Report the `report.md` path and a severity-count summary plus any coverage gaps.
