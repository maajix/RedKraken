#!/usr/bin/env python3
"""Rebuild the unified topic-module playbook catalog and source manifest.

The importer (curate_kb.py) is a one-shot: its Notion source is gone and it must
not be re-run against the curated notes. Topic directories are the source of
truth: README.md is the reviewed interface and sibling Markdown files are
imported operator depth. This script keeps the single routing interface aligned
with that layout. Idempotent; safe to re-run.

Run:  python3 scripts/rebuild_catalog.py
"""
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"
CODE_REVIEW = PLAYBOOKS / "code-review"

SKILL_FAMILIES = {"injection", "auth-session", "http-protocol", "ssrf-xxe-file",
                  "deserialization", "client-side", "access-control", "agentic-ai"}

# Reviewed card id -> operator-facing topic module. Storage follows the stable
# subject a caller searches for rather than the card's provenance or vintage.
TOPIC_BY_CARD = {
    "agentic-mcp-trust-boundaries": "agentic-ai",
    "api-inventory-resource-consumption": "api",
    "api-stateful-business-logic": "api-authorization",
    "attack-surface-architecture-mapping": "attack-surface",
    "authentication-mfa-recovery-lifecycle": "authentication",
    "browser-messaging-dom-clobbering": "browser-messaging",
    "browser-policy-framing": "browser-framing",
    "browser-realtime-xsleaks": "browser-realtime",
    "browser-request-integrity-policy": "request-integrity",
    "browser-script-execution-contexts": "browser-script",
    "browser-storage-client-templates": "browser-storage",
    "client-side-path-traversal": "client-side-path-traversal",
    "cms-extension-platform-boundaries": "cms",
    "command-directory-entity-injection": "command-directory-injection",
    "cookie-parser-differentials": "cookies",
    "deployment-configuration-exposure": "deployment",
    "exceptional-condition-security": "exceptional-conditions",
    "external-resource-ownership": "external-resources",
    "file-upload-processing-boundaries": "file-upload",
    "framework-routing-trust-boundaries": "routing",
    "graphql-authorization-cost": "graphql",
    "grpc-streaming-authorization": "grpc",
    "http2-desync": "http-desync",
    "identity-parser-differentials": "identity-parsing",
    "identity-provisioning-role-lifecycle": "identity-lifecycle",
    "information-disclosure-debug-artifacts": "information-disclosure",
    "nosql-operator-injection": "nosql-injection",
    "oauth-security-bcp": "oauth",
    "orm-relational-filter-leaks": "orm",
    "race-conditions-state-machines": "race-conditions",
    "realtime-sse-webrtc-authorization": "realtime",
    "relational-query-boundaries": "sql-injection",
    "request-parameter-authority-differentials": "request-parsing",
    "secrets-cryptographic-controls": "secrets",
    "security-logging-alerting": "logging",
    "server-file-resolution-boundaries": "file-resolution",
    "software-supply-chain-integrity": "supply-chain",
    "spreadsheet-formula-injection": "spreadsheet-injection",
    "ssti-error-oracles": "ssti",
    "structured-interpreter-injection": "structured-injection",
    "token-jose-verification-boundaries": "jwt-jose",
    "transaction-integrity-payment-workflows": "payment-workflows",
    "untrusted-data-deserialization": "deserialization",
    "url-parser-ssrf-routing": "ssrf-url-routing",
    "web-cache-normalization": "web-cache",
    "webauthn-passkeys": "webauthn",
    "webhook-event-authenticity": "webhooks",
    "workload-nonhuman-identity-lifecycle": "workload-identities",
}

# Imported note slug -> reviewed topic card (methodology first, operator depth second).
MODERN_XREF = {
    "auto-scanners": "attack-surface-architecture-mapping",
    "broken-link-hijacking": "external-resource-ownership",
    "cves": "attack-surface-architecture-mapping",
    "dangling-markup": "browser-script-execution-contexts",
    "ffuf": "attack-surface-architecture-mapping",
    "http-attacks-tls-attacks": "deployment-configuration-exposure",
    "rate-limit-bypass": "api-inventory-resource-consumption",
    "shells": "command-directory-entity-injection",
    "smtp-header-injection": "structured-interpreter-injection",
    "type-juggling": "authentication-mfa-recovery-lifecycle",
    "uuids": "api-stateful-business-logic",
    "waf-bypasses": "request-parameter-authority-differentials",
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
TOPIC_REFS_BEGIN = "<!-- BEGIN GENERATED TOPIC REFERENCES -->"
TOPIC_REFS_END = "<!-- END GENERATED TOPIC REFERENCES -->"


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


def load_reviewed_topics():
    topics = []
    for path in sorted(PLAYBOOKS.glob("*/README.md")):
        if path.parent == CODE_REVIEW:
            continue
        fm = parse_fm(path.read_text(encoding="utf-8"))
        if fm.get("review_status") != "source-reviewed":
            raise ValueError(f"{path.relative_to(ROOT)}: topic README must be source-reviewed")
        raw_id = fm.get("id")
        card_id = raw_id.removeprefix("modern-") if isinstance(raw_id, str) else raw_id
        expected_topic = TOPIC_BY_CARD.get(card_id)
        if expected_topic != path.parent.name:
            raise ValueError(
                f"{path.relative_to(ROOT)}: id {raw_id!r} maps to {expected_topic!r}"
            )
        topics.append({
            "topic": path.parent.name,
            "id": card_id,
            "title": fm.get("title", card_id),
            "family": fm.get("family", "misc"),
            "path": path.relative_to(PLAYBOOKS).as_posix(),
        })
    return topics


def load_imported_playbooks():
    out = []
    for path in sorted(PLAYBOOKS.glob("*/*.md")):
        if path.name == "README.md" or path.parent == CODE_REVIEW:
            continue
        slug = path.stem
        fm = parse_fm(path.read_text(encoding="utf-8"))
        if fm.get("review_status") != "imported-unreviewed":
            continue
        card = MODERN_XREF.get(slug)
        if not card:
            raise ValueError(f"{path.relative_to(ROOT)}: missing reviewed topic mapping")
        expected_topic = TOPIC_BY_CARD[card]
        if path.parent.name != expected_topic:
            raise ValueError(
                f"{path.relative_to(ROOT)}: expected topic {expected_topic!r}"
            )
        tags = fm.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        out.append({
            "slug": slug,
            "topic": path.parent.name,
            "path": path.relative_to(PLAYBOOKS).as_posix(),
            "technique": fm.get("technique", slug),
            "family": fm.get("family", "misc"),
            "severity": fm.get("severity_hint", "medium"),
            "tags": tags,
            "review_status": fm.get("review_status", "imported-unreviewed"),
        })
    return out


def safe_table(v):
    return str(v).replace("|", "\\|").replace("\n", " ")


def load_sink_packs():
    packs = []
    for path in sorted(CODE_REVIEW.glob("sinks-*.md")):
        text = path.read_text(encoding="utf-8")
        title = re.search(r"(?m)^# (.+)$", text)
        packs.append({
            "language": path.stem.removeprefix("sinks-"),
            "title": title.group(1) if title else path.stem,
            "path": path.relative_to(PLAYBOOKS).as_posix(),
        })
    return packs


def sync_topic_readmes(topics, pbs):
    refs_by_topic = {}
    for playbook in pbs:
        refs_by_topic.setdefault(playbook["topic"], []).append(playbook)
    block_re = re.compile(
        rf"\n*{re.escape(TOPIC_REFS_BEGIN)}.*?{re.escape(TOPIC_REFS_END)}\n*",
        re.DOTALL,
    )
    for topic in topics:
        path = PLAYBOOKS / topic["path"]
        text = block_re.sub("\n\n", path.read_text(encoding="utf-8")).rstrip() + "\n"
        refs = sorted(
            refs_by_topic.get(topic["topic"], []),
            key=lambda item: item["technique"].lower(),
        )
        if not refs:
            path.write_text(text, encoding="utf-8")
            continue
        lines = [
            TOPIC_REFS_BEGIN,
            "## Imported operator references",
            "",
            "These sibling notes provide payload and command depth. They remain",
            "`imported-unreviewed`; validate commands and prose before use.",
            "",
        ]
        for ref in refs:
            lines.append(
                f"- [{ref['technique']}]({Path(ref['path']).name}) — "
                f"severity hint: {ref['severity']}"
            )
        lines.append(TOPIC_REFS_END)
        source_heading = "\n## Sources\n"
        if source_heading not in text:
            raise ValueError(f"{path.relative_to(ROOT)}: missing Sources section")
        before, sources = text.split(source_heading, 1)
        path.write_text(
            before.rstrip()
            + "\n\n"
            + "\n".join(lines)
            + "\n\n## Sources\n"
            + sources.lstrip(),
            encoding="utf-8",
        )


def write_catalog(topics, pbs, sinks):
    by_fam = {}
    for p in pbs:
        by_fam.setdefault(p["family"], []).append(p)
    refs_by_topic = {}
    for p in pbs:
        refs_by_topic.setdefault(p["topic"], []).append(p)
    lines = ["# Playbook Catalog — signal → topic → playbook", "",
             "One routing interface for black-box methodology, imported operator depth, "
             "and white-box sink packs. Open a topic's `README.md` first; consult sibling "
             "notes only when the reviewed interface routes you there.", "",
             f"**{len(topics)} reviewed topics · {len(pbs)} imported references · "
             f"{len(sinks)} code sink packs.**", "",
             "> Generated by `scripts/rebuild_catalog.py`. Do not edit by hand.", "",
             "## Topic entrypoints", "",
             "| topic | family | reviewed methodology | imported depth |",
             "|---|---|---|---|"]
    for topic in sorted(topics, key=lambda item: item["topic"]):
        refs = sorted(refs_by_topic.get(topic["topic"], []), key=lambda item: item["slug"])
        ref_links = ", ".join(f"`{item['path']}`" for item in refs) or "—"
        lines.append(
            f"| {topic['topic']} | {topic['family']} | `{topic['path']}` | {ref_links} |"
        )
    lines.append("")

    for fam in sorted(by_fam, key=lambda k: (k not in SKILL_FAMILIES, k)):
        mark = "✅ skill" if fam in SKILL_FAMILIES else "📄 reference"
        rows = sorted(by_fam[fam], key=lambda p: p["technique"].lower())
        lines += [f"## {fam}  ({mark})  — {len(rows)} imported references", "",
                  "| technique | severity | topic | playbook | tags |", "|---|---|---|---|---|"]
        for p in rows:
            lines.append(f"| {safe_table(p['technique'])} | {p['severity']} | "
                         f"`{p['topic']}/README.md` | `{p['path']}` | "
                         f"{safe_table(', '.join(p['tags'][:5]))} |")
        lines.append("")

    lines += ["## White-box code review", "",
              "Start with `code-review/README.md`, then load the language pack.", "",
              "| language | sink pack |", "|---|---|"]
    for sink in sinks:
        lines.append(f"| {sink['language']} | `{sink['path']}` |")
    lines.append("")

    (PLAYBOOKS / "_catalog.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return len(topics), len(pbs), len(sinks), len(by_fam)


def reconcile_sources(pbs):
    path = PLAYBOOKS / "_sources.tsv"
    if not path.is_file():
        return 0
    slugs = {p["slug"] for p in pbs}
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f, delimiter="\t"))
    header, body = rows[0], rows[1:]
    kept = [r for r in body if r and r[0] in slugs]
    dropped = [r[0] for r in body if r and r[0] not in slugs]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        for r in kept:
            w.writerow(r)
    return dropped


def main():
    topics = load_reviewed_topics()
    pbs = load_imported_playbooks()
    sinks = load_sink_packs()
    sync_topic_readmes(topics, pbs)
    topic_count, imported_count, sink_count, fams = write_catalog(topics, pbs, sinks)
    dropped = reconcile_sources(pbs)
    print(
        f"catalog: {topic_count} reviewed topics, {imported_count} imported references, "
        f"{sink_count} sink packs across {fams} families"
    )
    if dropped:
        print(f"_sources.tsv: dropped {len(dropped)} orphan rows: {dropped}")


if __name__ == "__main__":
    main()
