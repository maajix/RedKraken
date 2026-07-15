#!/usr/bin/env bash
# Backwards-compatible entry point for the locked finding store.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/lib/finding_store.py" "$@"
