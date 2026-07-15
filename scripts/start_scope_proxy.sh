#!/usr/bin/env bash
# Start the HTTP(S) enforcement proxy for one engagement.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGAGEMENT="${1:-}"
PORT="${2:-18080}"
TOOL="${3:-}"
[ -n "$ENGAGEMENT" ] || { echo "usage: $0 <engagement-dir> [port] [tool-name]" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "invalid port" >&2; exit 2; }
[[ -z "$TOOL" || "$TOOL" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid tool name" >&2; exit 2; }
command -v mitmdump >/dev/null 2>&1 || { echo "mitmdump missing (OSS: github.com/mitmproxy/mitmproxy)" >&2; exit 1; }
export PENTEST_ENGAGEMENT_DIR="$(cd "$ENGAGEMENT" && pwd)"
export PENTEST_PROXY_TOOL="$TOOL"
exec mitmdump --listen-host 127.0.0.1 --listen-port "$PORT" --set block_global=false -s "$ROOT/lib/scope_proxy.py"
