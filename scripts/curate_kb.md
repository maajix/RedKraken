# KB curation — messy Notion notes → lossless playbook library

One-time (re-runnable) pass that turns the raw Notion web-attack export into a uniform,
searchable, **lossless** playbook library under `playbooks/web/`. Nothing is cut: every note
is copied verbatim to `_raw/` and every code block is preserved in its playbook.

## Run

```bash
python3 scripts/curate_kb.py [SRC_DIR] [DEST_DIR]
# defaults: SRC = the Notion Overview/Web export, DEST = playbooks/web
bash scripts/check_coverage.sh        # gate: 0 unmapped, raw==manifest → "nothing cut"
```

## What it produces (in `playbooks/web/`)

| Output | Meaning |
|---|---|
| `_raw/<relpath>.md` | Byte-exact copy of each source note (UUIDs stripped from names). Provenance + fallback. |
| `<slug>.md` | Curated playbook: front-matter (`technique/family/severity_hint/tags/source`) + a **quick-index** of every payload/command block + the full cleaned body. |
| `_catalog.md` | Routing table: **signal → technique → playbook**, grouped by family (✅ = has a hunting skill). |
| `_sources.tsv` | Coverage manifest: `slug  rawpath  technique  family  severity  tags` — one row per note. |
| `_skipped.txt` | Notes skipped as empty (<25 non-space chars), with reason. Should be empty. |

## How it classifies (in `curate_kb.py`)

- **Family** — first matching regex in `FAMILY_RULES` over `lower(relpath + title)`; falls back to `misc`
  (a valid reference bucket, not a cut). Skill families: injection, auth-session, http-protocol,
  ssrf-xxe-file, deserialization, client-side. Reference families: api, cms, cloud, recon-tools, misc.
- **Severity hint** — first match in `SEV_RULES` (critical/high/medium/low); default medium. A hint for
  triage only — the real severity is set per finding during the engagement.
- **Tags** — parsed from the note's `Tags:` line(s).
- **Skips** — the `Tags/` taxonomy dir and empty notes. Everything else is curated.

## Losslessness guarantee

- `_raw/` is a verbatim copy → the original is always recoverable.
- `clean_body()` is fence-aware: inside ``` code fences nothing is touched (all payloads/commands kept);
  outside, it only drops Notion chrome (Status/Tags/Created lines, images, internal-link wrappers — external
  http links kept).
- `check_coverage.sh` fails if any `_raw` note is missing from the manifest, or counts drift.

## Re-running

Safe and idempotent — overwrites `<slug>.md`, `_raw/`, `_catalog.md`, `_sources.tsv`. Re-run after editing
`FAMILY_RULES`/`SEV_RULES` to re-classify (e.g. move a `misc` note into a family), then re-run the coverage gate.
