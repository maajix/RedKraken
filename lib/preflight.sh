#!/usr/bin/env bash
# preflight.sh — tool-doctor for Fedora. Probes the expected toolbox, reports
# installed vs missing/broken, and (with --install) auto-installs the missing ones.
# Never silently assumes a tool exists.
#
# Usage:
#   preflight.sh              report only (default)
#   preflight.sh --install    install ALL missing tools
#   preflight.sh --install-core   install only missing core tools
#
# Install methods: dnf (sudo) | go install | pipx | gem. Package managers
# (golang/pipx/rubygems) are bootstrapped via dnf when a tool needs them.
# Exit: 0 if all CORE tools present (after any install), else 1.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="report"
case "${1:-}" in
  --install) MODE="install" ;;
  --install-core) MODE="install-core" ;;
  "" ) ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

# go/pipx put binaries here — make the probe see freshly-installed tools.
export PATH="$HOME/go/bin:$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

# name|group|method|target
TOOLS=$(cat <<'EOF'
curl|core|dnf|curl
jq|core|dnf|jq
python3|core|dnf|python3
pyyaml|core|pip|PyYAML==6.0.3
go|helper|dnf|golang
pipx|helper|dnf|pipx
gem|helper|dnf|rubygems
httpx|recon|go|github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0
katana|recon|go|github.com/projectdiscovery/katana/cmd/katana@v1.6.1
ffuf|recon|go|github.com/ffuf/ffuf/v2@v2.1.0
gobuster|recon|go|github.com/OJ/gobuster/v3@latest
feroxbuster|recon|dnf|feroxbuster
nuclei|recon|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0
nikto|recon|dnf|nikto
whatweb|recon|dnf|whatweb
wafw00f|recon|pipx|wafw00f
subfinder|recon|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
dnsx|recon|go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest
gau|recon|go|github.com/lc/gau/v2/cmd/gau@latest
waybackurls|recon|go|github.com/tomnomnom/waybackurls@latest
paramspider|recon|pipx|git+https://github.com/devanshbatham/paramspider
amass|recon|go|github.com/owasp-amass/amass/v4/...@master
sqlmap|exploit|dnf|sqlmap
dalfox|exploit|go|github.com/hahwul/dalfox/v2@latest
jwt-tool|exploit|pipx|git+https://github.com/ticarpi/jwt_tool
wpscan|exploit|gem|wpscan
nmap|exploit|dnf|nmap
openssl|exploit|dnf|openssl
mitmdump|browser|pipx|mitmproxy==12.2.3
playwright|browser|npm|playwright@1.61.1
zaproxy|browser|binary|download ZAP v2.17.0 from https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0
schemathesis|api|pipx|schemathesis==4.22.3
grpcurl|api|go|github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3
restler|api|binary|build a pinned release from https://github.com/microsoft/restler-fuzzer
EOF
)

present() {
  case "$1" in
    pyyaml) python3 -c 'import yaml' >/dev/null 2>&1 ;;
    *) command -v "$1" >/dev/null 2>&1 ;;
  esac
}

output_contains() {
  local needle="$1" output
  shift
  output="$("$@" 2>&1)" || return 1
  [[ "$output" == *"$needle"* ]]
}

healthy() {
  present "$1" || return 1
  case "$1" in
    pyyaml) python3 -c 'import yaml; raise SystemExit(yaml.__version__ != "6.0.3")' ;;
    httpx) output_contains 'v1.9.0' timeout 5 httpx -version ;;
    katana) output_contains 'v1.6.1' timeout 5 katana -version ;;
    ffuf) output_contains '2.1.0' timeout 5 ffuf -V ;;
    nuclei) output_contains 'v3.8.0' timeout 5 nuclei -version ;;
    whatweb) timeout 5 "$ROOT/scripts/run_whatweb.sh" --version >/dev/null 2>&1 ;;
    mitmdump) output_contains 'Mitmproxy: 12.2.3' timeout 5 mitmdump --version && output_contains 'Version: 6.0.3' pipx runpip mitmproxy show PyYAML ;;
    playwright) output_contains '1.61.1' timeout 5 playwright --version ;;
    zaproxy) local output; output="$(timeout 10 zaproxy -version 2>&1 || true)"; [[ "$output" == *'2.17.0'* ]] ;;
    schemathesis) output_contains '4.22.3' timeout 5 schemathesis --version ;;
    grpcurl) output_contains $'mod\tgithub.com/fullstorydev/grpcurl\tv1.9.3' go version -m "$(command -v grpcurl)" ;;
    *) return 0 ;;
  esac
}

have() { healthy "$1"; }

hint() { # method target -> human install hint
  case "$1" in
    dnf)  echo "sudo dnf install -y $2" ;;
    go)   echo "go install $2" ;;
    pipx) echo "pipx install $2" ;;
    gem)  echo "gem install --user-install $2" ;;
    pip)  echo "python3 -m pip install --user '$2'" ;;
    npm)  echo "npm install -g '$2'" ;;
    binary) echo "$2" ;;
  esac
}

bootstrap_for() { # ensure the package manager for a method exists
  case "$1" in
    go)   have go   || { echo "  · bootstrapping Go (sudo dnf install -y golang)"; sudo dnf install -y golang >/dev/null 2>&1; } ;;
    pipx) have pipx || { echo "  · bootstrapping pipx (sudo dnf install -y pipx)"; sudo dnf install -y pipx >/dev/null 2>&1; pipx ensurepath >/dev/null 2>&1; } ;;
    gem)  have gem  || { echo "  · bootstrapping Ruby (sudo dnf install -y rubygems ruby-devel)"; sudo dnf install -y rubygems ruby-devel >/dev/null 2>&1; } ;;
    pip)  python3 -m pip --version >/dev/null 2>&1 || { echo "  · bootstrapping pip"; sudo dnf install -y python3-pip >/dev/null 2>&1; } ;;
    npm)  have npm || { echo "  · bootstrapping npm"; sudo dnf install -y nodejs-npm >/dev/null 2>&1; } ;;
  esac
}

install_one() { # name method target -> 0 ok / 1 fail
  local name="$1" method="$2" target="$3"
  [ "$method" = binary ] && { echo "  · $name needs manual install: $target"; return 1; }
  bootstrap_for "$method"
  echo "  · installing $name ($method)"
  case "$method" in
    dnf)  sudo dnf install -y "$target"            >/dev/null 2>&1 ;;
    go)   go install "$target"                     >/dev/null 2>&1 ;;
    pipx) pipx install --force "$target"           >/dev/null 2>&1 ;;
    gem)  gem install --user-install "$target"     >/dev/null 2>&1 ;;
    pip)  python3 -m pip install --user "$target"  >/dev/null 2>&1 ;;
    npm)  npm install -g "$target"                 >/dev/null 2>&1 ;;
  esac
  if [ "$name" = mitmdump ]; then
    pipx inject --force mitmproxy 'PyYAML==6.0.3' >/dev/null 2>&1 || return 1
  fi
  have "$name"
}

# ---- pass 1: report ----
echo "=== preflight (Fedora/dnf) — mode: $MODE ==="
printf '%-16s %-8s %s\n' "TOOL" "GROUP" "STATUS"
declare -a MISSING=()
n_ok=0; n_miss=0; miss_core=0
while IFS='|' read -r name group method target; do
  [ -n "$name" ] || continue
  if healthy "$name"; then
    printf '%-16s %-8s ✓ installed\n' "$name" "$group"; n_ok=$((n_ok+1))
  else
    if present "$name"; then state="BROKEN"; else state="MISSING"; fi
    printf '%-16s %-8s ✗ %-7s → %s\n' "$name" "$group" "$state" "$(hint "$method" "$target")"
    n_miss=$((n_miss+1)); [ "$group" = core ] && miss_core=$((miss_core+1))
    MISSING+=("$name|$group|$method|$target")
  fi
done <<<"$TOOLS"
echo "-------------------------------------------------------"
echo "installed=$n_ok  missing=$n_miss  missing_core=$miss_core"

# ---- pass 2: install (opt-in) ----
if [ "$MODE" != report ] && [ "${#MISSING[@]}" -gt 0 ]; then
  echo ""; echo "=== installing missing tools ==="
  if ! sudo -v 2>/dev/null; then echo "NOTE: sudo needed for dnf installs; you may be prompted."; fi
  done_ok=0; done_fail=0
  for row in "${MISSING[@]}"; do
    IFS='|' read -r name group method target <<<"$row"
    [ "$MODE" = install-core ] && [ "$group" != core ] && continue
    if install_one "$name" "$method" "$target"; then echo "    ✓ $name OK"; done_ok=$((done_ok+1))
    else echo "    ✗ $name FAILED — install manually: $(hint "$method" "$target")"; done_fail=$((done_fail+1)); fi
  done
  echo "-------------------------------------------------------"
  echo "installed_now=$done_ok  still_failing=$done_fail"
  echo "If go/pipx tools aren't found, add to your shell rc:  export PATH=\"\$PATH:\$HOME/go/bin:\$HOME/.local/bin\""
  # recompute core status
  miss_core=0
  while IFS='|' read -r name group method target; do
    [ "$group" = core ] && ! have "$name" && miss_core=$((miss_core+1))
  done <<<"$TOOLS"
fi

if [ "$miss_core" -gt 0 ]; then
  echo "WARNING: core tools still missing — the loop cannot run reliably. Notify the operator (run: preflight.sh --install-core)."
  exit 1
fi
[ "$n_miss" -gt 0 ] && [ "$MODE" = report ] && \
  echo "NOTE: optional tools missing — run 'preflight.sh --install' to auto-install, or affected techniques are reported as 'tool unavailable' (never skipped silently)."
exit 0
