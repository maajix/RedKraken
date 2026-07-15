#!/usr/bin/env bash
# Authoritative scope gate. The strict parser lives in scope_check.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/lib/scope_check.py" "$@"
