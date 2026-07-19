---
name: code-recon
description: Whitebox code reconnaissance & attack-surface mapping from source — detect languages/frameworks, entry points, routes, auth middleware, dependency manifests, config/secret locations, trust boundaries; run the free static scanners within audit scope and persist a structured code map. Use during the map phase of a /audit run, before per-family auditing.
---

# Code Recon (map the source, don't judge it)

You map the attack surface **from source**. You produce leads and a structured
code map; you do **not** confirm vulnerabilities (that's the `code-auditor`).
Obey `scope-guard` (authorization) and `tool-preflight` (notify on missing
scanners — never silently skip).

`$HARNESS` = repo root. Engagement dir is in `.active_engagement`.

## Authorization & scope
- You must be **authorized to audit this code**. If `source_path` is missing or
  authorization is unclear → stop and ask the operator.
- Pure source reading has **no network target**, so the scope hook passes it.
  Any command that touches a live host (grey-box) still scope-checks via
  `lib/scope_check.sh`.
- Honor `audit_include` / `audit_exclude` from `engagement.yaml` (always exclude
  `node_modules`, `vendor`, `dist`, `.git` unless told otherwise).
- Claude hooks audit scanner commands automatically; use `lib/audit.sh` only outside Claude Code.

## 1. Detect languages & frameworks
From manifests at `source_path`:
`package.json` (Node; check deps for express/next), `requirements.txt`/`pyproject.toml`/`Pipfile` (Python; django/flask/fastapi), `composer.json` (PHP; laravel), `pom.xml`/`build.gradle` (Java; spring), `Gemfile` (Ruby; rails), `go.mod` (Go). Count files per language (`rg --files -g '*.py' | wc -l`).

## 2. Map entry points, routes & auth
Grep for route/handler declarations and auth guards, per detected framework:
- Flask/FastAPI `@app.route`/`@router.*`; Django `urls.py` + views; Express `app.(get|post|...)`/`router.*`; Spring `@*Mapping`; Rails `config/routes.rb`; Go `HandleFunc`/framework routers.
- Auth middleware/guards: `@login_required`, `@PreAuthorize`, `before_action`, auth middleware registration. For each entry point record whether a guard is present (`auth: none|session|role|...`) — this seeds the `access-control` family.

## 3. Locate config, secrets surface, trust boundaries
Config files (`settings.py`, `application.yml`, `.env*`, `config/*`), Dockerfiles, IaC (`*.tf`, `k8s/*.yaml`), CI (`.github/workflows/*`). These seed `secrets-crypto` and `config-iac`.

## 4. Run the free scanners (leads → `state/scan-raw/`)
Run whatever `code_preflight` reports present; skip+note the rest. Always run the ripgrep sink sweeps (they need only `rg`). Resolve `OUT="$PENTEST_ENGAGEMENT_DIR/state/scan-raw"` as an absolute path before changing directories. Examples (SRC = resolved source_path):
```
rg -n --no-heading -f <sink patterns from playbooks/code-review/sinks-<lang>.md> "$SRC"   # always
OUT="$PENTEST_ENGAGEMENT_DIR/state/scan-raw"; mkdir -p "$OUT"
opengrep scan --sarif -o "$OUT/opengrep.sarif" --config <local rules> "$SRC"  # if present + rules available
njsscan --sarif -o "$OUT/njsscan.sarif" "$SRC"        # Node
bandit -r -f json -o "$OUT/bandit.json" "$SRC"        # Python
( cd "$SRC" && gosec -fmt sarif -out "$OUT/gosec.sarif" ./... )  # Go module
brakeman -f json -o "$OUT/brakeman.json" "$SRC"       # Rails
osv-scanner scan source --recursive --format json --output-file "$OUT/osv.json" "$SRC"   # deps
trivy fs --scanners vuln,secret,misconfig,license --format json -o "$OUT/trivy-fs.json" "$SRC"
gitleaks detect --source "$SRC" --report-format sarif --report-path "$OUT/gitleaks.sarif"  # secrets incl. git history
hadolint --format sarif "$SRC/Dockerfile" > "$OUT/hadolint.sarif"   # if Dockerfile
```
> No opengrep rule pack and no login (we never use `--config auto`): rely on the
> native linters + ripgrep sink packs as the baseline; use opengrep/semgrep only
> with a locally-available ruleset. Missing scanner ⇒ record the family it would
> have covered as a coverage gap.

## 5. Produce `state/codemap.json`
```json
{"source_path":"./src",
 "languages":[{"lang":"python","files":123,"frameworks":["flask"]}],
 "entry_points":[{"kind":"route","method":"GET","path":"/item","handler":"routes/item.py:11","auth":"none"}],
 "manifests":["requirements.txt"],
 "config_files":["settings.py",".env.example"],
 "iac_files":["Dockerfile"],
 "scanners_run":["ripgrep","bandit","trivy","osv-scanner","gitleaks"],
 "scanners_missing":["opengrep"],
 "raw":["state/scan-raw/bandit.json","state/scan-raw/trivy-fs.json"]}
```
Return a concise summary: languages/frameworks, entry-point count (and how many unguarded), which scanners ran vs missing, and the top candidate families with rough lead counts. Hand back to the orchestrator; do not start auditing.
