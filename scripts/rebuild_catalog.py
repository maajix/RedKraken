#!/usr/bin/env python3
"""Rebuild playbooks/web/_catalog.md and reconcile _sources.tsv from the actual
curated *.md front-matter.

The importer (curate_kb.py) is a one-shot: its Notion source is gone and it must
not be re-run against playbooks/web/. From here the curated files are the source
of truth and are hand-maintained (merged, scrubbed, retired). This script keeps
the routing catalog and coverage manifest consistent with whatever files exist,
so hand-curation no longer drifts from the catalog. Idempotent; safe to re-run.

Run:  python3 scripts/rebuild_catalog.py
"""
import csv
import json
import os
import re

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "playbooks", "web")

SKILL_FAMILIES = {"injection", "auth-session", "http-protocol", "ssrf-xxe-file",
                  "deserialization", "client-side", "access-control", "agentic-ai"}

# web slug -> reviewed modern card (prefer for methodology; web note is payload depth)
MODERN_XREF = {
    "xxe": "command-directory-entity-injection",
    "xpath-injections": "structured-interpreter-injection",
    "ldap-injections": "command-directory-entity-injection",
    "os-command-injection": "command-directory-entity-injection",
    "open-redirection": "url-parser-ssrf-routing",
    "dns-rebinding": "url-parser-ssrf-routing",
    "pdf-generators": "url-parser-ssrf-routing",
    "tabnabbing": "browser-policy-framing",
    "cors-xssi": "browser-policy-framing",
    "http-attacks-verb-tampering": "framework-routing-trust-boundaries",
    "status-code-bypass": "framework-routing-trust-boundaries",
    "xss": "browser-script-execution-contexts",
    "xss-paramspider": "browser-script-execution-contexts",
    "sqli": "relational-query-boundaries",
    "sqli-advanced-sqli-techniques": "relational-query-boundaries",
    "sqli-advanced-sqlmap": "relational-query-boundaries",
    "sqli-blind-sql-injection": "relational-query-boundaries",
    "sqli-custom-tampering": "relational-query-boundaries",
    "sqli-file-read": "relational-query-boundaries",
    "sqli-identifying-vulnerabilities": "relational-query-boundaries",
    "sqli-intro-to-mssql-sql-server": "relational-query-boundaries",
    "sqli-introduction-postgresql": "relational-query-boundaries",
    "sqli-leaking-netntlm-hashes": "relational-query-boundaries",
    "sqli-mitigation": "relational-query-boundaries",
    "sqli-out-of-band-dns": "relational-query-boundaries",
    "sqli-postgresql-specific-techniques": "relational-query-boundaries",
    "sqli-remote-code-execution": "relational-query-boundaries",
    "sqli-time-based-sqli": "relational-query-boundaries",
    "lfi": "server-file-resolution-boundaries",
    "php-filter-chain-lfi-rce": "server-file-resolution-boundaries",
    "file-upload": "file-upload-processing-boundaries",
    "ssrf": "url-parser-ssrf-routing",
    "oauth2": "oauth-security-bcp",
    "oauth2-attack-via-google-oauth2-playground": "oauth-security-bcp",
    "ssti": "ssti-error-oracles",
    "deserialization-attacks": "untrusted-data-deserialization",
    "websocket-attacks": "browser-realtime-xsleaks",
    "prototype-pollution": "browser-messaging-dom-clobbering",
    "prototype-pollution-clientside-pp": "browser-messaging-dom-clobbering",
    "dom-vulnerabilities": "browser-messaging-dom-clobbering",
    "cors": "browser-request-integrity-policy",
    "csrf": "browser-request-integrity-policy",
    "clickjacking": "browser-policy-framing",
    "cache-poisoning": "web-cache-normalization",
    "api-graphql": "graphql-authorization-cost",
    "api": "api-inventory-resource-consumption",
    "api-rest": "api-inventory-resource-consumption",
    "api-soap": "api-inventory-resource-consumption",
    "http-attacks-request-smuggling-and-http-desync": "http2-desync",
    "http-attacks-http-2-downgrading": "http2-desync",
    "idor": "api-stateful-business-logic",
    "saml": "identity-parser-differentials",
    "llm": "agentic-mcp-trust-boundaries",
    "race-conditions-and-timing-attacks": "race-conditions-state-machines",
    "cms-wordpress": "cms-extension-platform-boundaries",
    "cms-drupal": "cms-extension-platform-boundaries",
    "cms-joomla": "cms-extension-platform-boundaries",
    "cloud-aws-cognito": "authentication-mfa-recovery-lifecycle",
    "sign-up-login-register": "authentication-mfa-recovery-lifecycle",
    "http-attacks-password-reset": "authentication-mfa-recovery-lifecycle",
    "jwt": "token-jose-verification-boundaries",
    "parameter-pollution": "request-parameter-authority-differentials",
    "http-attacks-host-header": "request-parameter-authority-differentials",
    "http-attacks-crlf-injection-and-response-splitting": "request-parameter-authority-differentials",
}

FM_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_fm(text):
    m = FM_RE.match(text)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).splitlines():
        km = re.match(r"([A-Za-z0-9_]+):\s*(.*)", line)
        if not km:
            continue
        k, v = km.group(1), km.group(2).strip()
        try:
            fm[k] = json.loads(v)
        except Exception:
            fm[k] = v.strip('"')
    return fm


def load_playbooks():
    out = []
    for fn in sorted(os.listdir(WEB)):
        if not fn.endswith(".md") or fn.startswith("_"):
            continue
        slug = fn[:-3]
        fm = parse_fm(open(os.path.join(WEB, fn), encoding="utf-8").read())
        tags = fm.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        out.append({
            "slug": slug,
            "technique": fm.get("technique", slug),
            "family": fm.get("family", "misc"),
            "severity": fm.get("severity_hint", "medium"),
            "tags": tags,
            "review_status": fm.get("review_status", "imported-unreviewed"),
        })
    return out


def safe_table(v):
    return str(v).replace("|", "\\|").replace("\n", " ")


def write_catalog(pbs):
    by_fam = {}
    for p in pbs:
        by_fam.setdefault(p["family"], []).append(p)
    lines = ["# Web Playbook Catalog — signal → technique → playbook", "",
             "Routing table for triage and hunters. Families with a dedicated hunting "
             "skill are marked ✅; others are reference playbooks the recon-agent / "
             "hunters consult opportunistically.", "",
             f"**{len(pbs)} playbooks across {len(by_fam)} families.**", "",
             "> Generated by `scripts/rebuild_catalog.py` from each note's front-matter. "
             "Do not edit by hand; re-run the script after adding, merging, or retiring a playbook.", ""]

    xref = [(p, MODERN_XREF[p["slug"]]) for p in pbs if p["slug"] in MODERN_XREF]
    if xref:
        lines += ["## Reviewed cards (prefer these for methodology)", "",
                  "For these techniques a source-reviewed, non-destructive-by-default card "
                  "exists under `../modern/`. Read it first for the test approach; use the "
                  "imported web note below for payload/command depth.", "",
                  "| web note | reviewed card |", "|---|---|"]
        for p, card in sorted(xref, key=lambda x: x[0]["slug"]):
            lines.append(f"| `{p['slug']}.md` | `../modern/{card}.md` |")
        lines.append("")

    for fam in sorted(by_fam, key=lambda k: (k not in SKILL_FAMILIES, k)):
        mark = "✅ skill" if fam in SKILL_FAMILIES else "📄 reference"
        rows = sorted(by_fam[fam], key=lambda p: p["technique"].lower())
        lines += [f"## {fam}  ({mark})  — {len(rows)} playbooks", "",
                  "| technique | severity | playbook | tags |", "|---|---|---|---|"]
        for p in rows:
            lines.append(f"| {safe_table(p['technique'])} | {p['severity']} | "
                         f"`{p['slug']}.md` | {safe_table(', '.join(p['tags'][:5]))} |")
        lines.append("")

    open(os.path.join(WEB, "_catalog.md"), "w", encoding="utf-8").write("\n".join(lines).rstrip() + "\n")
    return len(pbs), len(by_fam)


def reconcile_sources(pbs):
    path = os.path.join(WEB, "_sources.tsv")
    if not os.path.isfile(path):
        return 0
    slugs = {p["slug"] for p in pbs}
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f, delimiter="\t"))
    header, body = rows[0], rows[1:]
    kept = [r for r in body if r and r[0] in slugs]
    dropped = [r[0] for r in body if r and r[0] not in slugs]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        for r in kept:
            w.writerow(r)
    return dropped


def main():
    pbs = load_playbooks()
    n, fams = write_catalog(pbs)
    dropped = reconcile_sources(pbs)
    print(f"catalog: {n} playbooks across {fams} families")
    if dropped:
        print(f"_sources.tsv: dropped {len(dropped)} orphan rows: {dropped}")


if __name__ == "__main__":
    main()
