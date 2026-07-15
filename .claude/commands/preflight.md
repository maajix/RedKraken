---
description: Tool-doctor — report the installed/missing toolbox; optionally auto-install (Fedora/dnf).
argument-hint: [--install | --install-core]
---

Run the toolbox preflight:

```bash
bash lib/preflight.sh $ARGUMENTS
```

Then summarise for the operator:
- which tools are installed vs missing (and what each missing tool is needed for),
- whether any **core** tool is missing (the loop can't run reliably without core),
- the exact fix: `bash lib/preflight.sh --install` (auto-install via dnf + go/pipx/gem) or the per-tool install hint shown.

If `$ARGUMENTS` already requested an install, report what got installed and what still failed (and the PATH note for go/pipx binaries). Never claim a tool is available unless preflight shows it installed.

For a **whitebox / code audit** (`/audit`), also run the code-audit toolbox doctor:

```bash
bash lib/code_preflight.sh $ARGUMENTS
```

It probes the free, no-API-key scanners (opengrep, trivy, osv-scanner, gitleaks, hadolint, per-language linters). Only `rg`/`jq` are core — missing scanners are optional (the audit still runs on the LLM auditor + ripgrep sink packs) and are reported as per-family coverage gaps.
