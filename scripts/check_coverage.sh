#!/usr/bin/env bash
# Coverage gate: assert every verbatim _raw note maps to a curated playbook (nothing cut).
# Self-contained — checks the committed _raw/ copies against _sources.tsv; no Notion export needed.
# Exit 0 iff 0 unmapped notes and raw==manifest. Usage: bash scripts/check_coverage.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB="$ROOT/playbooks/web"; RAW="$WEB/_raw"; SRC="$WEB/_sources.tsv"

[ -d "$RAW" ] || { echo "FAIL: missing $RAW — run: python3 scripts/curate_kb.py"; exit 1; }
[ -f "$SRC" ] || { echo "FAIL: missing $SRC — run: python3 scripts/curate_kb.py"; exit 1; }

mapped="$(mktemp)"; trap 'rm -f "$mapped"' EXIT
tail -n +2 "$SRC" | cut -f2 | sort -u > "$mapped"   # col 2 = rawpath (relative to _raw/)

total=0; unmapped=0
while IFS= read -r -d '' f; do
  total=$((total+1)); rel="${f#"$RAW"/}"
  grep -qxF "$rel" "$mapped" || { echo "  UNMAPPED  $rel"; unmapped=$((unmapped+1)); }
done < <(find "$RAW" -type f -name '*.md' -print0)

pb=$(find "$WEB" -maxdepth 1 -type f -name '*.md' ! -name '_*' | wc -l)
rows=$(tail -n +2 "$SRC" | wc -l)
distinct=$(tail -n +2 "$SRC" | cut -f1 | sort -u | wc -l)
duplicate_raw=$(tail -n +2 "$SRC" | cut -f2 | sort | uniq -d | wc -l)
echo "raw_notes=$total  manifest_rows=$rows  playbooks=$pb  unmapped=$unmapped"
[ "$unmapped" -eq 0 ]   || { echo "FAIL: $unmapped raw note(s) not in manifest — coverage gap."; exit 1; }
[ "$total" -eq "$rows" ] || { echo "FAIL: $total raw notes vs $rows manifest rows — mismatch."; exit 1; }
[ "$pb" -eq "$distinct" ] || { echo "FAIL: $pb curated playbooks vs $distinct distinct slugs — mismatch."; exit 1; }
[ "$duplicate_raw" -eq 0 ] || { echo "FAIL: $duplicate_raw duplicate raw path(s) in manifest."; exit 1; }
while IFS=$'\t' read -r slug _; do
  [ "$slug" = slug ] && continue
  [ -f "$WEB/$slug.md" ] || { echo "FAIL: catalog target missing for slug: $slug"; exit 1; }
done < "$SRC"
echo "PASS: full coverage — every note curated, nothing cut."
