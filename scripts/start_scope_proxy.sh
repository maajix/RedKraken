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
# Idempotent start: a second `exec mitmdump` on an already-bound port dies with
# "[Errno 98] address already in use" -- which reads like a crash and can mask a
# still-healthy proxy. If a scope proxy is already listening here, no-op; if a
# foreign process holds the port, refuse rather than fight it. (A sandbox-blind
# liveness probe is what produces spurious "proxy down" restarts; run checks with
# the sandbox disabled.)
if command -v ss >/dev/null 2>&1; then
  holder="$(ss -ltnp 2>/dev/null | grep -E "127\.0\.0\.1:${PORT}\b" | head -n1 || true)"
  if [ -n "$holder" ]; then
    if printf '%s\n' "$holder" | grep -q 'mitmdump'; then
      echo "scope proxy already listening on 127.0.0.1:$PORT; nothing to do" >&2
      exit 0
    fi
    echo "127.0.0.1:$PORT is held by a non-proxy process; refusing to start:" >&2
    printf '  %s\n' "$holder" >&2
    exit 1
  fi
elif timeout 1 bash -c ": </dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
  echo "something is already listening on 127.0.0.1:$PORT; assuming scope proxy is up; nothing to do" >&2
  exit 0
fi
# Hand off to the durable supervisor (lib/proxy_supervisor.py): it owns exactly
# one proxy per engagement+port via an flock, respawns mitmdump if it exits
# (bounded by a crash-loop budget), and -- launched detached with setsid --
# stays alive independently of THIS shell/agent. That detachment is the
# root-cause fix: the old foreground `exec mitmdump` died whenever its launching
# context exited, dropping scope enforcement mid-run. Liveness is checked by
# audit recency (`proxy_supervisor.py health <engagement>`), never ps/ss, so it
# stays correct under the future network-namespace isolation.
LOG="$PENTEST_ENGAGEMENT_DIR/state/scope-proxy-$PORT.log"
mkdir -p "$(dirname "$LOG")"
if command -v setsid >/dev/null 2>&1; then
  setsid python3 "$ROOT/lib/proxy_supervisor.py" supervise "$PENTEST_ENGAGEMENT_DIR" "$PORT" "$TOOL" >>"$LOG" 2>&1 </dev/null &
  echo "scope proxy supervisor started detached (pid $!); log: $LOG" >&2
else
  exec python3 "$ROOT/lib/proxy_supervisor.py" supervise "$PENTEST_ENGAGEMENT_DIR" "$PORT" "$TOOL"
fi
