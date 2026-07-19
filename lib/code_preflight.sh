#!/usr/bin/env bash
# code_preflight.sh — tool-doctor for the WHITEBOX (code-audit) toolbox.
# Free, no-API-key scanners only. Mirrors lib/preflight.sh: probes the expected
# tools, reports installed vs missing/broken, and (with --install) auto-installs
# the ones we can (dnf/go/pipx/gem). binary/script tools are advisory (printed,
# not auto-run) to avoid piping remote installers.
#
# Usage:
#   code_preflight.sh              report only (default)
#   code_preflight.sh --install    auto-install missing dnf/go/pipx/gem tools
#
# Design note: /audit degrades gracefully. The real engine is the LLM auditor +
# the ripgrep sink packs (`playbooks/code-review/`) — so only `rg` and `jq` are CORE.
# Scanners are optional accelerators; a missing scanner is surfaced as coverage
# (e.g. "supply-chain family skipped: osv-scanner missing"), never silently
# skipped. Exit: 0 if all CORE tools present, else 1.
set -uo pipefail

MODE="report"
case "${1:-}" in
  --install) MODE="install" ;;
  "" ) ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"

# name|group|method|target
# groups: core (plumbing) · sast · lang (native linters) · sca · secrets · iac · deep
# methods: dnf|go|pipx|gem auto-install; binary|script are advisory (hint only).
TOOLS=$(cat <<'EOF'
rg|core|dnf|ripgrep
jq|core|dnf|jq
pyyaml|core|pip|PyYAML==6.0.3
opengrep|sast|script|curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash  (OSS, no login)
semgrep|sast|pipx|semgrep
njsscan|lang|pipx|njsscan
bandit|lang|pipx|bandit
gosec|lang|go|github.com/securego/gosec/v2/cmd/gosec@latest
brakeman|lang|gem|brakeman
osv-scanner|sca|go|github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.2.4
trivy|sca|binary|curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin
gitleaks|secrets|go|github.com/gitleaks/gitleaks/v8@latest
hadolint|iac|binary|download release from https://github.com/hadolint/hadolint/releases
grype|deep|binary|curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin
syft|deep|binary|curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin
checkov|deep|pipx|checkov
trufflehog|deep|go|github.com/trufflesecurity/trufflehog/v3@latest
joern|deep|script|see https://docs.joern.io/installation (Apache-2, JVM; deep cross-function taint)
EOF
)

have() {
  case "$1" in
    pyyaml) python3 -c 'import yaml' >/dev/null 2>&1 ;;
    httpx) command -v httpx >/dev/null 2>&1 && timeout 5 httpx -version 2>&1 | grep -qiE 'current (httpx )?version|projectdiscovery' ;;
    *) command -v "$1" >/dev/null 2>&1 ;;
  esac
}

hint() { # method target -> human install hint
  case "$1" in
    dnf)    echo "sudo dnf install -y $2" ;;
    go)     echo "go install $2" ;;
    pipx)   echo "pipx install $2" ;;
    gem)    echo "gem install --user-install $2" ;;
    pip)    echo "python3 -m pip install --user '$2'" ;;
    binary) echo "$2" ;;
    script) echo "$2" ;;
  esac
}

bootstrap_for() {
  case "$1" in
    go)   have go   || { echo "  · bootstrapping Go (sudo dnf install -y golang)"; sudo dnf install -y golang >/dev/null 2>&1; } ;;
    pipx) have pipx || { echo "  · bootstrapping pipx (sudo dnf install -y pipx)"; sudo dnf install -y pipx >/dev/null 2>&1; pipx ensurepath >/dev/null 2>&1; } ;;
    gem)  have gem  || { echo "  · bootstrapping Ruby (sudo dnf install -y rubygems ruby-devel)"; sudo dnf install -y rubygems ruby-devel >/dev/null 2>&1; } ;;
    pip)  python3 -m pip --version >/dev/null 2>&1 || { echo "  · bootstrapping pip"; sudo dnf install -y python3-pip >/dev/null 2>&1; } ;;
  esac
}

install_one() { # name method target -> 0 ok / 1 fail
  local name="$1" method="$2" target="$3"
  case "$method" in
    binary|script)
      echo "  · $name needs manual install: $(hint "$method" "$target")"; return 1 ;;
  esac
  bootstrap_for "$method"
  echo "  · installing $name ($method)"
  case "$method" in
    dnf)  sudo dnf install -y "$target"        >/dev/null 2>&1 ;;
    go)   go install "$target"                 >/dev/null 2>&1 ;;
    pipx) pipx install "$target"               >/dev/null 2>&1 ;;
    gem)  gem install --user-install "$target" >/dev/null 2>&1 ;;
    pip)  python3 -m pip install --user "$target" >/dev/null 2>&1 ;;
  esac
  have "$name"
}

# ---- pass 1: report ----
echo "=== code-audit preflight (whitebox scanners — free, no API key) — mode: $MODE ==="
printf '%-16s %-8s %s\n' "TOOL" "GROUP" "STATUS"
declare -a MISSING=()
n_ok=0; n_miss=0; miss_core=0
while IFS='|' read -r name group method target; do
  [ -n "$name" ] || continue
  if have "$name"; then
    printf '%-16s %-8s ✓ installed\n' "$name" "$group"; n_ok=$((n_ok+1))
  else
    printf '%-16s %-8s ✗ MISSING  → %s\n' "$name" "$group" "$(hint "$method" "$target")"
    n_miss=$((n_miss+1)); [ "$group" = core ] && miss_core=$((miss_core+1))
    MISSING+=("$name|$group|$method|$target")
  fi
done <<<"$TOOLS"
echo "-------------------------------------------------------"
echo "installed=$n_ok  missing=$n_miss  missing_core=$miss_core"

# ---- pass 2: install (opt-in; dnf/go/pipx/gem only) ----
if [ "$MODE" = install ] && [ "${#MISSING[@]}" -gt 0 ]; then
  echo ""; echo "=== installing missing tools (binary/script tools are advisory) ==="
  if ! sudo -v 2>/dev/null; then echo "NOTE: sudo needed for dnf installs; you may be prompted."; fi
  done_ok=0; done_fail=0
  for row in "${MISSING[@]}"; do
    IFS='|' read -r name group method target <<<"$row"
    if install_one "$name" "$method" "$target"; then echo "    ✓ $name OK"; done_ok=$((done_ok+1))
    else echo "    ✗ $name not auto-installed — $(hint "$method" "$target")"; done_fail=$((done_fail+1)); fi
  done
  echo "-------------------------------------------------------"
  echo "installed_now=$done_ok  still_manual/failing=$done_fail"
  echo "If go/pipx tools aren't found, add to your shell rc:  export PATH=\"\$PATH:\$HOME/go/bin:\$HOME/.local/bin\""
  miss_core=0
  while IFS='|' read -r name group method target; do
    [ "$group" = core ] && ! have "$name" && miss_core=$((miss_core+1))
  done <<<"$TOOLS"
fi

if [ "$miss_core" -gt 0 ]; then
  echo "WARNING: core tools (rg/jq/PyYAML) missing — install them before running the harness."
  exit 1
fi
[ "$n_miss" -gt 0 ] && [ "$MODE" = report ] && \
  echo "NOTE: scanners missing are OPTIONAL — /audit still runs on the LLM auditor + ripgrep sink packs. Missing scanners are reported as coverage gaps per family, never skipped silently. Run 'bash lib/code_preflight.sh --install' for the auto-installable ones."
exit 0
