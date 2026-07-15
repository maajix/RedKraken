#!/usr/bin/env bash
# Self-check for lib/code_preflight.sh — REPORT-ONLY. Never runs --install
# (which could sudo/network). Validates the report structure + arg handling.
set -u
HARNESS="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HARNESS/lib/code_preflight.sh"
fail=0
assert(){ if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }

out="$(bash "$SCRIPT" 2>&1)"; rc=$?

assert "prints a TOOL table header"     'grep -q "TOOL" <<<"$out"'
assert "lists opengrep (sast)"          'grep -qi "opengrep" <<<"$out"'
assert "lists trivy (sca)"              'grep -qi "trivy" <<<"$out"'
assert "lists osv-scanner (sca)"        'grep -qi "osv-scanner" <<<"$out"'
assert "lists gitleaks (secrets)"       'grep -qi "gitleaks" <<<"$out"'
assert "lists bandit (lang linter)"     'grep -qi "bandit" <<<"$out"'
assert "shows installed/MISSING status" 'grep -qiE "installed|MISSING" <<<"$out"'
assert "report exit code is 0 or 1"     '[ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]'

bash "$SCRIPT" --bogus >/dev/null 2>&1; brc=$?
assert "unknown arg exits 2"            '[ "$brc" -eq 2 ]'

[ "$fail" -eq 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
