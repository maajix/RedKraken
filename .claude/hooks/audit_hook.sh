#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export HARNESS_AUDIT_HOOK=1
exec python3 "$ROOT/lib/audit_event.py"
