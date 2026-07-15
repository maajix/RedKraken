#!/usr/bin/env bash
# Structural gate for source-reviewed modern attack coverage. No network access.
set -euo pipefail
HARNESS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HARNESS"

python3 scripts/check_modern_coverage.py

echo "PASS: baseline IDs, family skills, and blackbox routing are consistent"
