#!/usr/bin/env bash
# Smoke test for the whitebox building blocks. Deterministic — does NOT require
# an LLM run. Verifies: the vulnerable fixture has a clear source->sink, the
# sink packs are complete, the catalog routes families, and the auditor carries
# the anti-hallucination guardrail. End-to-end /audit is a manual acceptance step.
set -u
HARNESS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HARNESS"
fail=0
assert(){ if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }

FIX="tests/fixtures/vuln-sample/app.py"
# search helper: prefer ripgrep (what the packs assume), fall back to grep
if command -v rg >/dev/null 2>&1; then S(){ rg -n "$1" "$2"; }; else S(){ grep -nE "$1" "$2"; }; fi

assert "fixture exists" '[ -f "$FIX" ]'

src_line=$(S 'request\.args\.get' "$FIX" | head -1 | cut -d: -f1)
sink_line=$(S 'execute\(' "$FIX" | head -1 | cut -d: -f1)
assert "fixture has a tainted source" '[ -n "$src_line" ]'
assert "fixture has a SQL sink"       '[ -n "$sink_line" ]'
assert "source precedes sink (traceable)" '[ -n "$src_line" ] && [ -n "$sink_line" ] && [ "$src_line" -lt "$sink_line" ]'

assert "python sink pack covers execute()" 'grep -q "execute" playbooks/code-review/sinks-python.md'
assert "catalog routes injection family"   'grep -q "| injection |" playbooks/_catalog.md'
assert "auditor has anti-hallucination guardrail" \
  'grep -qi "confirmed" .claude/agents/code-auditor.md && grep -qi "only if" .claude/agents/code-auditor.md'

# all six sink packs structurally complete
for f in js python php java ruby go; do
  p="playbooks/code-review/sinks-$f.md"
  if grep -q "## Sources" "$p" && grep -q "## Sinks" "$p" && grep -q "rg -n" "$p" && grep -q "## Confirm" "$p"; then
    echo "PASS: sink pack $f complete"
  else
    echo "FAIL: sink pack $f incomplete"; fail=1
  fi
done

# all 10 families are routing targets in the catalog
for fam in injection auth-session http-protocol ssrf-xxe-file deserialization client-side access-control secrets-crypto supply-chain config-iac; do
  if grep -q "| $fam |" playbooks/_catalog.md; then echo "PASS: catalog has $fam"; else echo "FAIL: catalog missing $fam"; fail=1; fi
done

[ "$fail" -eq 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
