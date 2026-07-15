#!/usr/bin/env bash
# Deterministic, proxy-enforced OpenAPI/GraphQL scan with mutation opt-in.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGAGEMENT="${1:-}"; SCHEMA="${2:-}"; BASE_URL="${3:-}"; shift $(( $# >= 3 ? 3 : $# ))
[ -n "$ENGAGEMENT" ] && [ -n "$SCHEMA" ] && [ -n "$BASE_URL" ] || {
  echo "usage: $0 <engagement> <schema-file-or-url> <base-url> [--allow-mutation] [--seed N] [--max-examples N]" >&2; exit 2;
}
ALLOW_MUTATION=false; SEED=1; MAX_EXAMPLES=50
while [ "$#" -gt 0 ]; do
  case "$1" in
    --allow-mutation) ALLOW_MUTATION=true; shift ;;
    --seed) SEED="${2:?missing seed}"; shift 2 ;;
    --max-examples) MAX_EXAMPLES="${2:?missing max examples}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$SEED" =~ ^[0-9]+$ ]] || { echo "seed must be an integer" >&2; exit 2; }
[[ "$MAX_EXAMPLES" =~ ^[1-9][0-9]*$ ]] || { echo "max examples must be positive" >&2; exit 2; }
[ "$MAX_EXAMPLES" -le 1000 ] || { echo "max examples capped at 1000" >&2; exit 2; }

export PENTEST_ENGAGEMENT_DIR="$(cd "$ENGAGEMENT" && pwd)"
bash "$ROOT/lib/scope_check.sh" "$BASE_URL" "$PENTEST_ENGAGEMENT_DIR" >/dev/null
if [[ "$SCHEMA" =~ ^https?:// ]]; then
  bash "$ROOT/lib/scope_check.sh" "$SCHEMA" "$PENTEST_ENGAGEMENT_DIR" >/dev/null
else
  SCHEMA="$(realpath "$SCHEMA")"; [ -f "$SCHEMA" ] || { echo "schema missing" >&2; exit 2; }
fi
PROXY="${PENTEST_PROXY:-}"
[ -n "$PROXY" ] || { echo "PENTEST_PROXY is required; start scripts/start_scope_proxy.sh first" >&2; exit 2; }
if ! command -v schemathesis >/dev/null 2>&1; then
  echo "schemathesis missing (OSS: github.com/schemathesis/schemathesis)" >&2; exit 1
fi

if [ "$ALLOW_MUTATION" = true ]; then
  python3 - "$PENTEST_ENGAGEMENT_DIR/engagement.yaml" <<'PY'
import sys, yaml
config = yaml.safe_load(open(sys.argv[1]))
if config.get("destructive_allowed") is not True:
    raise SystemExit("--allow-mutation requires destructive_allowed: true")
PY
fi

RUN_ID="$(jq -r '.run_id // "manual"' "$PENTEST_ENGAGEMENT_DIR/state/run.json" 2>/dev/null || echo manual)"
OUT="$PENTEST_ENGAGEMENT_DIR/state/scan-raw/schemathesis-$RUN_ID"
mkdir -p "$OUT"
ARGS=(run "$SCHEMA" --url "$BASE_URL" --workers 1 --seed "$SEED" --max-examples "$MAX_EXAMPLES"
  --generation-deterministic --max-redirects 0 --proxy "$PROXY" --output-sanitize true
  --report ndjson,har --report-ndjson-path "$OUT/events.ndjson" --report-har-path "$OUT/network.har")
RATE_LIMIT="$(python3 - "$ROOT" "$PENTEST_ENGAGEMENT_DIR/engagement.yaml" <<'PY'
import sys
sys.path.insert(0, f"{sys.argv[1]}/lib")
from harness_config import load_engagement, rate_policy
policy = rate_policy(load_engagement(sys.argv[2]), "schemathesis")
print(f'{policy["requests_per_second"]:g}' if policy else "")
PY
)"
if [ -n "$RATE_LIMIT" ]; then
  ARGS+=(--rate-limit "${RATE_LIMIT}/s")
fi
if [ "$ALLOW_MUTATION" = true ]; then
  ARGS+=(--phases examples,coverage,fuzzing,stateful)
else
  ARGS+=(--phases examples,coverage,fuzzing --exclude-method POST --exclude-method PUT --exclude-method PATCH --exclude-method DELETE)
fi
( cd "$PENTEST_ENGAGEMENT_DIR" && schemathesis "${ARGS[@]}" ) 2>&1 | tee "$OUT/run.log"
