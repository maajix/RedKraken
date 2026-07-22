#!/usr/bin/env bash
# Run one hook-visible HTTP tool through the shared enforcement proxy.
set -euo pipefail
umask 077
[ "$#" -gt 0 ] || { echo "usage: $0 <http-tool> [args...]" >&2; exit 2; }

proxy_url="http://127.0.0.1:18080"
export PENTEST_PROXY="$proxy_url"
export HTTP_PROXY="$proxy_url" HTTPS_PROXY="$proxy_url" ALL_PROXY="$proxy_url"
export http_proxy="$proxy_url" https_proxy="$proxy_url" all_proxy="$proxy_url"
export NO_PROXY= no_proxy=

tool="$1"
shift
expect_proxy_value=false
for argument in "$@"; do
  if [ "$expect_proxy_value" = true ]; then
    [ "$argument" = "$proxy_url" ] || {
      echo "proxy override must use $proxy_url" >&2
      exit 2
    }
    expect_proxy_value=false
    continue
  fi
  case "$argument" in
    --proxy|-x) expect_proxy_value=true ;;
    --proxy=*) [ "${argument#*=}" = "$proxy_url" ] || { echo "unsafe proxy override" >&2; exit 2; } ;;
    -x*) [ "${argument#-x}" = "$proxy_url" ] || { echo "unsafe proxy override" >&2; exit 2; } ;;
    --noproxy|--noproxy=*|--no-proxy) echo "proxy bypass option denied" >&2; exit 2 ;;
    --next) [ "$(basename "$tool")" != curl ] || { echo "curl --next is denied" >&2; exit 2; } ;;
  esac
done
[ "$expect_proxy_value" = false ] || { echo "missing proxy value" >&2; exit 2; }

if [ "$(basename "$tool")" = curl ]; then
  # -q first disables ~/.curlrc; final options override any permitted config.
  exec "$tool" -q "$@" --proxy "$proxy_url" --noproxy ""
fi
exec "$tool" "$@"
