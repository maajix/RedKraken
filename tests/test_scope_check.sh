#!/usr/bin/env bash
# Self-test for lib/scope_check.sh. Exits non-zero if any assertion fails.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SC="$HERE/../lib/scope_check.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ENG="$TMP/engagement.yaml"
cat > "$ENG" <<'YAML'
name: test
targets:
  - app.target.com
  - "*.api.target.com"
  - "*.target.com"
  - 10.0.0.0/24
out_of_scope:
  - admin.target.com   # deny must win over *.target.com
intent: test
destructive_allowed: false
YAML

pass=0; fail=0
# assert <expected IN|OUT> <input> [engagement]
assert() {
  local want="$1" input="$2" eng="${3:-$ENG}" got rc
  got="$(bash "$SC" "$input" "$eng" 2>/dev/null)"; rc=$?
  local res="OUT"; [ $rc -eq 0 ] && res="IN"
  if [ "$res" = "$want" ]; then pass=$((pass+1)); printf '  ok   %-4s %s\n' "$want" "$input"
  else fail=$((fail+1)); printf '  FAIL want=%s got=%s  %s\n' "$want" "$res" "$input"; fi
}

echo "scope_check self-test:"
assert IN  "app.target.com"
assert IN  "foo.api.target.com"
assert IN  "www.target.com"
assert IN  "https://app.target.com/login?id=1#frag"
assert IN  "http://user:pass@app.target.com:8443/x"
assert IN  "10.0.0.5"
assert OUT "admin.target.com"                 # deny precedence
assert OUT "target.com"                        # apex not covered by *.target.com
assert OUT "evil-target.com"                   # look-alike must NOT pass
assert OUT "target.com.evil.com"               # suffix-confusion must NOT pass
assert OUT "other.com"
assert OUT "10.0.1.5"                           # outside /24
assert OUT "app.target.com" "/nonexistent/eng.yaml"   # fail closed: no engagement

echo "-------------------------------------------"
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
