#!/usr/bin/env bash
# Isolate Fedora's packaged WhatWeb from incompatible /usr/local Ruby gems.
set -euo pipefail
command -v whatweb >/dev/null 2>&1 || { echo "whatweb missing" >&2; exit 1; }
if [ -d /usr/share/gems ]; then
  export GEM_HOME=/usr/share/gems
  export GEM_PATH=/usr/share/gems
  unset RUBYLIB RUBYOPT
fi
exec whatweb "$@"
