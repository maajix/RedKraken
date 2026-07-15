---
name: tool-preflight
description: Verify a CLI tool is installed and working before relying on it, and NOTIFY the operator when a tool is missing or broken instead of silently skipping a technique. Use whenever about to invoke an external pentest tool (sqlmap, ffuf, nuclei, jwt-tool, …).
---

# Tool Preflight

A missing tool must never become a silently skipped vulnerability class. Surface it.

## Check before use

```bash
command -v <tool> >/dev/null 2>&1 || echo "MISSING:<tool>"
```
Run the full probe with `bash "$HARNESS/lib/preflight.sh"` at engagement start.

## When a tool is missing or broken

1. **Notify the operator clearly** — one line: which tool, what it was for, and the fix:
   > ⚠️ `jwt-tool` not installed — needed for JWT attacks on `/api/login`. Install: `bash lib/preflight.sh --install` (or `pipx install git+https://github.com/ticarpi/jwt_tool`).
2. **Fall back** to an equivalent if one is installed (e.g. `feroxbuster`↔`ffuf`↔`gobuster`; `dalfox`↔manual XSS; `gau`↔`waybackurls`). Note the substitution.
3. If no equivalent exists, record `status: not-tested` with `status_reason: tool unavailable: <tool>` against the relevant endpoint so coverage remains machine-readable.

## "Broken", not just "missing"

A tool that is installed but errors (missing wordlist, bad version, network/permission error) is also a notify-and-record case — don't silently treat its empty output as "no vulnerability". Distinguish *tool failed* from *target not vulnerable*.

## Auto-install (opt-in, Fedora/dnf)

The operator may run `bash "$HARNESS/lib/preflight.sh" --install` to auto-install missing tools (dnf for system packages; go/pipx/gem otherwise). Only the operator triggers installs; suggest it, don't assume it ran.

`$HARNESS` = repo root.
