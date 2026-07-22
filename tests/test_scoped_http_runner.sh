#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

actual="$(
  HTTP_PROXY=http://unsafe.invalid NO_PROXY='*' \
    "$ROOT/scripts/run_scoped_http.sh" sh -c \
    'printf "%s\n" "$PENTEST_PROXY" "$HTTP_PROXY" "$HTTPS_PROXY" "$ALL_PROXY" "$http_proxy" "$https_proxy" "$all_proxy" "$NO_PROXY" "$no_proxy"'
)"
expected="$(printf '%s\n' \
  http://127.0.0.1:18080 http://127.0.0.1:18080 http://127.0.0.1:18080 \
  http://127.0.0.1:18080 http://127.0.0.1:18080 http://127.0.0.1:18080 \
  http://127.0.0.1:18080 '' '')"
[ "$actual" = "$expected" ] || { echo "scoped HTTP environment mismatch" >&2; exit 1; }

task_tmp="$(mktemp -d)"
trap 'rm -rf "$task_tmp"' EXIT
printf '%s\n' '#!/usr/bin/env bash' 'printf "%q\n" "$@"' >"$task_tmp/curl"
chmod +x "$task_tmp/curl"
curl_args="$(PATH="$task_tmp:$PATH" "$ROOT/scripts/run_scoped_http.sh" curl https://app.example.test/)"
printf '%s\n' "$curl_args" | grep -qx -- '-q'
printf '%s\n' "$curl_args" | grep -qx -- '--proxy'
printf '%s\n' "$curl_args" | grep -qx -- 'http://127.0.0.1:18080'
printf '%s\n' "$curl_args" | grep -qx -- '--noproxy'
if "$ROOT/scripts/run_scoped_http.sh" curl --next https://app.example.test/ >/dev/null 2>&1; then
  echo "curl --next unexpectedly allowed" >&2
  exit 1
fi
if "$ROOT/scripts/run_scoped_http.sh" curl --proxy http://127.0.0.1:9999 https://app.example.test/ >/dev/null 2>&1; then
  echo "proxy override unexpectedly allowed" >&2
  exit 1
fi
echo "scoped HTTP runner: ok"
