#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/redkraken-vhost-test-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/engagement/state" "$TMP/bin"
cat > "$TMP/engagement/engagement.yaml" <<'YAML'
targets:
  - 192.0.2.10
  - '*.example.test'
out_of_scope:
  - evil.other.test
rate_limit_enabled: true
rate_limit:
  requests_per_second: 3
  burst: 3
  max_concurrency: 1
YAML
cat > "$TMP/candidates.txt" <<'WORDS'
hidden
www
evil.other.test
WORDS

cat > "$TMP/bin/fake-ffuf" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
wordlist=""; output=""; rate=""
while (($#)); do
  case "$1" in
    -w) wordlist="$2"; shift 2 ;;
    -o) output="$2"; shift 2 ;;
    -rate) rate="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp "$wordlist" "$FFUF_SEEN"
printf '%s' "$rate" > "$FFUF_RATE"
python3 - "$output" <<'PY'
import json, sys
json.dump({"results": [{"input": {"FUZZ": "hidden.example.test"}}]}, open(sys.argv[1], "w"))
PY
SH
chmod +x "$TMP/bin/fake-ffuf"

cat > "$TMP/bin/fake-curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
host=""; body=""; headers=""
while (($#)); do
  case "$1" in
    --resolve) host="${2%%:*}"; shift 2 ;;
    -o) body="$2"; shift 2 ;;
    -D) headers="$2"; shift 2 ;;
    -w) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "$host" >> "$CURL_SEEN"
if [[ "$host" == hidden.example.test ]]; then
  printf '<title>Hidden Admin</title> unique response\n' > "$body"
  printf 'HTTP/1.1 200 OK\nLocation: /admin\n' > "$headers"
else
  printf '<title>Default</title> wildcard response\n' > "$body"
  printf 'HTTP/1.1 200 OK\n' > "$headers"
fi
printf '200'
SH
chmod +x "$TMP/bin/fake-curl"

export FFUF_BIN="$TMP/bin/fake-ffuf" CURL_BIN="$TMP/bin/fake-curl"
export FFUF_SEEN="$TMP/ffuf-seen" FFUF_RATE="$TMP/ffuf-rate" CURL_SEEN="$TMP/curl-seen"
bash "$ROOT/scripts/run_vhost_discovery.sh" \
  "$TMP/engagement" "http://192.0.2.10" "192.0.2.10" "example.test" "$TMP/candidates.txt"

grep -qx 'hidden.example.test' "$FFUF_SEEN"
grep -qx 'www.example.test' "$FFUF_SEEN"
! grep -q 'evil.other.test' "$FFUF_SEEN"
[[ "$(cat "$FFUF_RATE")" == 3 ]]
python3 - "$TMP/engagement/state/targets.json" <<'PY'
import json, sys
targets = json.load(open(sys.argv[1]))
assert any(t.get("logical_host") == "hidden.example.test" and t.get("route_ip") == "192.0.2.10" for t in targets)
assert not any(t.get("logical_host") == "evil.other.test" for t in targets)
PY
[[ "$(stat -c %a "$TMP/engagement/state/scan-raw")" == 700 ]]
while IFS= read -r path; do
  [[ "$(stat -c %a "$path")" == 600 ]]
done < <(find "$TMP/engagement/state/scan-raw" -type f)
echo "PASS: scoped VHost discovery filters, rate-bounds, confirms, and records"
