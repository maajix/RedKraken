#!/usr/bin/env bash
# Scope-filtered VHost discovery with differential negative controls.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -ne 5 ]]; then
  echo "usage: $0 ENGAGEMENT BASE_URL ROUTE_IP DOMAIN WORDLIST" >&2
  exit 2
fi
ENGAGEMENT="$(realpath "$1")"
BASE_URL="$2"
ROUTE_IP="$3"
DOMAIN="${4,,}"
WORDLIST="$(realpath "$5")"
FFUF="${FFUF_BIN:-ffuf}"
CURL="${CURL_BIN:-curl}"
SLEEP="${SLEEP_BIN:-sleep}"
SCOPE="${SCOPE_CHECK_BIN:-$ROOT/lib/scope_check.sh}"
RAW="$ENGAGEMENT/state/scan-raw"
mkdir -p "$RAW"
chmod 700 "$ENGAGEMENT" "$ENGAGEMENT/state" "$RAW"

"$SCOPE" "$BASE_URL" "$ENGAGEMENT" >/dev/null
"$SCOPE" "$ROUTE_IP" "$ENGAGEMENT" >/dev/null
[[ "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || { echo "invalid domain" >&2; exit 2; }
[[ -f "$WORDLIST" && ! -L "$WORDLIST" ]] || { echo "wordlist must be a regular file" >&2; exit 2; }

read -r POLICY_FFUF_RATE CURL_DELAY < <(python3 - "$ROOT" "$ENGAGEMENT/engagement.yaml" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from lib.harness_config import load_engagement, rate_policy

config = load_engagement(sys.argv[2])
ffuf = rate_policy(config, "ffuf")
curl = rate_policy(config, "curl")
ffuf_rate = f'{float(ffuf["requests_per_second"]):g}' if ffuf else ""
curl_delay = 1.0 / float(curl["requests_per_second"]) if curl else ""
print(ffuf_rate, curl_delay)
PY
)

REQUIRED_HEADER_ARGS=()
HEADER_FILE="$(mktemp "$RAW/.required-headers.XXXXXX")"
if ! python3 - "$ROOT" "$ENGAGEMENT/engagement.yaml" > "$HEADER_FILE" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from lib.harness_config import load_engagement

config = load_engagement(sys.argv[2])
for name, value in (config.get("required_headers") or {}).items():
    if name.casefold() == "host":
        raise SystemExit("required_headers Host conflicts with VHost discovery")
    sys.stdout.write(f"{name}: {value}\0")
PY
then
  rm -f "$HEADER_FILE"
  exit 2
fi
while IFS= read -r -d '' header; do
  REQUIRED_HEADER_ARGS+=(-H "$header")
done < "$HEADER_FILE"
rm -f "$HEADER_FILE"

FILTERED="$RAW/vhost-filtered.txt"
: > "$FILTERED"
while IFS= read -r raw || [[ -n "$raw" ]]; do
  candidate="${raw%%[[:space:]]*}"
  candidate="${candidate,,}"
  [[ -n "$candidate" && "$candidate" != \#* ]] || continue
  [[ "$candidate" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || continue
  if [[ "$candidate" != *.* ]]; then candidate="$candidate.$DOMAIN"; fi
  if "$SCOPE" "$candidate" "$ENGAGEMENT" >/dev/null 2>&1; then
    printf '%s\n' "$candidate" >> "$FILTERED"
  fi
done < "$WORDLIST"
sort -u -o "$FILTERED" "$FILTERED"
chmod 600 "$FILTERED"
[[ -s "$FILTERED" ]] || { echo "no in-scope VHost candidates" >&2; exit 1; }

read -r SCHEME PORT < <(python3 - "$BASE_URL" <<'PY'
import sys
from urllib.parse import urlsplit
p = urlsplit(sys.argv[1])
if p.scheme not in {"http", "https"} or not p.hostname:
    raise SystemExit(2)
print(p.scheme, p.port or (443 if p.scheme == "https" else 80))
PY
)

signature() {
  local host="$1" label="$2"
  local body="$RAW/${label}.body" headers="$RAW/${label}.headers"
  local status size words title location digest
  if [[ -n "$CURL_DELAY" ]]; then "$SLEEP" "$CURL_DELAY"; fi
  status="$("$CURL" -ksS --max-time 15 --resolve "$host:$PORT:$ROUTE_IP" \
    "${REQUIRED_HEADER_ARGS[@]}" -H "Host: $host" -o "$body" -D "$headers" \
    -w '%{http_code}' "$SCHEME://$host:$PORT/")"
  chmod 600 "$body" "$headers"
  size="$(wc -c < "$body" | tr -d ' ')"
  words="$(wc -w < "$body" | tr -d ' ')"
  title="$(sed -nE 's@.*<[Tt][Ii][Tt][Ll][Ee]>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>.*@\1@p' "$body" | head -1 | tr '\t\r\n' '   ')"
  location="$(sed -nE 's/^[Ll]ocation:[[:space:]]*(.*)\r?$/\1/p' "$headers" | head -1 | tr '\t\r\n' '   ')"
  digest="$(sha256sum "$body" | cut -d' ' -f1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s' "$status" "$size" "$words" "$title" "$location" "$digest"
}

CONTROLS="$RAW/vhost-controls.tsv"
: > "$CONTROLS"
for number in 1 2 3; do
  control="rk-negative-${number}-${RANDOM}-$$.$DOMAIN"
  "$SCOPE" "$control" "$ENGAGEMENT" >/dev/null
  printf '%s\t%s\n' "$control" "$(signature "$control" "control-$number")" >> "$CONTROLS"
done
chmod 600 "$CONTROLS"

RATE_ARGS=()
if [[ -n "$POLICY_FFUF_RATE" ]]; then RATE_ARGS=(-rate "$POLICY_FFUF_RATE"); fi

FFUF_JSON="$RAW/vhost-ffuf.json"
"$FFUF" -u "$BASE_URL" "${REQUIRED_HEADER_ARGS[@]}" -H 'Host: FUZZ' \
  -w "$FILTERED" -of json -o "$FFUF_JSON" "${RATE_ARGS[@]}"
chmod 600 "$FFUF_JSON"
RESULTS="$RAW/vhost-results.txt"
python3 - "$FFUF_JSON" > "$RESULTS" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for result in data.get("results", []):
    value = (result.get("input") or {}).get("FUZZ")
    if isinstance(value, str):
        print(value)
PY
chmod 600 "$RESULTS"

CONFIRMED="$RAW/vhost-confirmed.jsonl"
: > "$CONFIRMED"
index=0
while IFS= read -r host; do
  [[ -n "$host" ]] || continue
  "$SCOPE" "$host" "$ENGAGEMENT" >/dev/null
  index=$((index + 1))
  fresh="rk-fresh-${index}-${RANDOM}-$$.$DOMAIN"
  "$SCOPE" "$fresh" "$ENGAGEMENT" >/dev/null
  candidate_sig="$(signature "$host" "candidate-$index")"
  control_sig="$(signature "$fresh" "fresh-control-$index")"
  if [[ "$candidate_sig" != "$control_sig" ]]; then
    python3 - "$host" "$ROUTE_IP" "$SCHEME" "$PORT" "$candidate_sig" >> "$CONFIRMED" <<'PY'
import json, sys
host, route, scheme, port, signature = sys.argv[1:]
print(json.dumps({"logical_host": host, "route_ip": route, "url": f"{scheme}://{host}:{port}", "signature_sha256": __import__('hashlib').sha256(signature.encode()).hexdigest()}, sort_keys=True))
PY
  fi
done < "$RESULTS"
chmod 600 "$CONFIRMED"

TARGETS="$ENGAGEMENT/state/targets.json"
python3 - "$TARGETS" "$CONFIRMED" <<'PY'
import json, os, sys, tempfile
target_path, confirmed_path = sys.argv[1:]
try:
    current = json.load(open(target_path)) if os.path.exists(target_path) else []
except (OSError, json.JSONDecodeError):
    raise SystemExit("targets.json is malformed; refusing overwrite")
if not isinstance(current, list):
    raise SystemExit("targets.json must be an array")
seen = {(item.get("logical_host"), item.get("route_ip")) for item in current if isinstance(item, dict)}
for line in open(confirmed_path):
    item = json.loads(line)
    key = (item["logical_host"], item["route_ip"])
    if key not in seen:
        current.append(item); seen.add(key)
directory = os.path.dirname(target_path)
fd, temporary = tempfile.mkstemp(prefix=".targets-", dir=directory)
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(current, handle, indent=2, sort_keys=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, target_path)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
PY
echo "confirmed=$(wc -l < "$CONFIRMED" | tr -d ' ') raw=$RAW"
