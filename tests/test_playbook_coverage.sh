#!/usr/bin/env bash
# Structural gate for source-reviewed topic coverage. No network access.
set -euo pipefail
HARNESS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HARNESS"

python3 scripts/check_playbook_coverage.py

echo "PASS: baseline IDs, family skills, and blackbox routing are consistent"
