#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v playwright >/dev/null 2>&1 || { echo "playwright missing" >&2; exit 1; }
export NODE_PATH="$(npm root -g)${NODE_PATH:+:$NODE_PATH}"
exec node "$ROOT/scripts/browser_capture.cjs" "$@"
