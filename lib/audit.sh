#!/usr/bin/env bash
# Compatibility wrapper. Claude Code tool calls are logged automatically by hooks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/lib/audit_event.py" "$@"
