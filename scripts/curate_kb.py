#!/usr/bin/env python3
"""Curate the raw Notion web-attack notes into a uniform, lossless playbook library.

For each source note (excluding the Tags/ taxonomy):
  * copy it verbatim to playbooks/web/_raw/<relpath>            (byte-exact provenance)
  * emit playbooks/web/<slug>.md with uniform front-matter, a quick-index of every
    payload/command code block, and the full cleaned body (all payloads preserved)
  * record it in playbooks/web/_sources.tsv                      (coverage manifest)

Lossless: every code block is kept; the verbatim original is always in _raw/.
Run:  python3 scripts/curate_kb.py [SRC_DIR] [DEST_DIR]
"""
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

SRC = sys.argv[1] if len(sys.argv) > 1 else (
    "/home/majix/Downloads/3fa6ed26-6c8d-4499-a24d-eaf01393c5b6_ExportBlock-a23e7c38-d0e7-4af2-a6da-138d6fb178c2/"
    "ExportBlock-a23e7c38-d0e7-4af2-a6da-138d6fb178c2-Part-1/Overview/Web")
DEST = sys.argv[2] if len(sys.argv) > 2 else "/home/majix/web-pentest-harness/playbooks/web"
CURATOR_VERSION = 2

UUID = re.compile(r" ?[0-9a-f]{32}")
STRIP_PREFIX = ("Web attacks/Web Attacks/",)   # noise prefix removed from slugs

FAMILY_RULES = [  # (regex over lower(relpath+title), family)  -- first match wins
    (r"\bidor\b|\bbola\b|\bbfla\b|access[ -]?control|authori[sz]ation|mass assignment|business[ -]?logic", "access-control"),
    (r"deserial|pickle|ysoserial|phpggc", "deserialization"),
    (r"\bllm\b|agentic|prompt injection|retrieval.augmented|\brag\b|model context protocol|\bmcp\b", "agentic-ai"),
    (r"\bxss\b|csrf|\bcors\b|xssi|\bdom\b|prototype pollution|open redirect|dangling|tabnab|clickjack|websocket|broken.link", "client-side"),
    (r"sqli|sql injection|nosql|\bldap\b|xpath|os command|command injection|\bssti\b|template inj", "injection"),
    (r"\bssrf\b|\bxxe\b|\blfi\b|file upload|php filter|dns rebinding|pdf generator|file read|file disclosure", "ssrf-xxe-file"),
    (r"\bjwt\b|oauth|\bsaml\b|sign up|login|register|password reset|type juggling|\buuid|session|rate.limit|cognito", "auth-session"),
    (r"request smuggling|http attacks|host.header|crlf|cache poisoning|verb tampering|http 2|downgrad|\btls\b|parameter pollution|status code|\b403\b|heartbleed|padding oracle|poodle|beast|crime|breach|drown|bleichenbacher", "http-protocol"),
    (r"^api/|graphql|\bsoap\b|\brest\b|kiterunner", "api"),
    (r"^cms/|wordpress|joomla|drupal|cmsmap", "cms"),
    (r"^cloud/|aws|cognito|azure|gcp", "cloud"),
    (r"^auto scanners/|nuclei|nikto|fuzzer", "recon-tools"),
]
SEV_RULES = [
    (r"rce|remote code execution|deserial|\bssti\b|command injection|file upload|sql injection|sqli|\bxxe\b|\blfi\b|php filter", "critical"),
    (r"\bssrf\b|request smuggling|\bjwt\b|\bsaml\b|oauth|account takeover|auth.*bypass|\bidor\b|netntlm", "high"),
    (r"\bxss\b|csrf|\bcors\b|prototype pollution|host.header|cache poisoning|open redirect|smtp|ldap|xpath", "medium"),
    (r"\btls\b|header|tabnab|clickjack|broken.link|info|uuid|status code", "low"),
]

def strip_uuid(s): return UUID.sub("", s)

def slugify(rel):
    s = rel
    for p in STRIP_PREFIX:
        if s.startswith(p): s = s[len(p):]
    s = strip_uuid(s)
    s = s[:-3] if s.lower().endswith(".md") else s
    s = s.lower().replace("/", "-").replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return re.sub(r"-{2,}", "-", s) or "note"

def detect(rules, text, default):
    for rx, val in rules:
        if re.search(rx, text): return val
    return default

def extract_tags(body):
    tags = []
    for line in body.splitlines()[:12]:
        m = re.match(r"\s*Tags(?: 2)?:\s*(.+)", line)
        if m:
            for part in m.group(1).split(","):
                name = re.split(r"\s*\(", part.strip())[0].strip()
                if name and name.lower() not in (t.lower() for t in tags):
                    tags.append(name)
    return tags[:12]

LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")
def delink(m):
    text, tgt = m.group(1), m.group(2)
    return m.group(0) if tgt.startswith(("http://", "https://")) else text

def clean_body(body):
    out, in_code = [], False
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code; out.append(line); continue
        if in_code: out.append(line); continue
        if re.match(r"\s*(Status|Tags|Tags 2|Erstellt|Created):", line): continue
        line = IMG.sub("", line)
        line = LINK.sub(delink, line)
        out.append(line)
    # collapse 3+ blank lines
    txt = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", txt).strip()

def code_index(body):
    labels, tools, in_code, buf = [], set(), False, []
    fence_info = ""
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            if not in_code:
                in_code, buf, fence_info = True, [], line.lstrip()[3:].strip()
            else:
                in_code = False
                first = next((b.strip() for b in buf if b.strip()), "")
                if first:
                    labels.append(((fence_info + ": ") if fence_info else "") + first[:90])
                for t in ("sqlmap","jwt_tool","ffuf","nuclei","nikto","dalfox","wpscan","curl","openssl",
                          "gobuster","feroxbuster","httpx","paramspider","ysoserial","phpggc","commix",
                          "subfinder","katana","gau","nmap","python3","wafw00f"):
                    if re.search(r"\b"+re.escape(t)+r"\b", "\n".join(buf)): tools.add(t)
            continue
        if in_code: buf.append(line)
    return labels, sorted(tools)

def title_of(body, rel):
    for line in body.splitlines():
        m = re.match(r"#\s+(.+)", line)
        if m: return m.group(1).strip()
    return strip_uuid(os.path.basename(rel))[:-3]


def safe_table(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def safe_tsv(value):
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def replace_destination(staged, destination):
    destination = os.path.abspath(destination)
    backup = f"{destination}.previous-{os.getpid()}"
    moved_old = False
    try:
        if os.path.exists(destination):
            os.replace(destination, backup)
            moved_old = True
        os.replace(staged, destination)
        if moved_old:
            shutil.rmtree(backup)
    except Exception:
        if moved_old and not os.path.exists(destination) and os.path.exists(backup):
            os.replace(backup, destination)
        raise

def main():
    destination = os.path.abspath(DEST)
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    staged = tempfile.mkdtemp(prefix=f".{os.path.basename(destination)}.staged-", dir=parent)
    raw_root = os.path.join(staged, "_raw")
    os.makedirs(raw_root, exist_ok=True)
    rows, skipped, catalog = [], [], {}
    seen_slugs, seen_raw = {}, {}
    for dirpath, dirnames, files in os.walk(SRC):
        dirnames.sort()
        files.sort()
        if os.sep + "Tags" + os.sep in dirpath + os.sep: continue
        for fn in files:
            if not fn.endswith(".md"): continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, SRC)
            try:
                body = open(full, encoding="utf-8", errors="replace").read()
            except Exception as e:
                skipped.append((rel, f"read error: {e}")); continue
            if len(re.sub(r"\s+", "", body)) < 25:
                skipped.append((rel, "empty")); continue
            rel_clean = strip_uuid(rel)
            if rel_clean in seen_raw:
                raise RuntimeError(f"raw path collision: {rel!r} and {seen_raw[rel_clean]!r} -> {rel_clean!r}")
            seen_raw[rel_clean] = rel
            # verbatim raw copy (lossless)
            raw_dst = os.path.join(raw_root, rel_clean)
            os.makedirs(os.path.dirname(raw_dst), exist_ok=True)
            shutil.copyfile(full, raw_dst)
            # curate
            title = title_of(body, rel)
            key = (rel + " " + title).lower()
            family = detect(FAMILY_RULES, key, "misc")
            sev = detect(SEV_RULES, key, "medium")
            tags = extract_tags(body)
            slug = slugify(rel)
            if slug in seen_slugs:
                raise RuntimeError(f"slug collision: {rel!r} and {seen_slugs[slug]!r} -> {slug!r}")
            seen_slugs[slug] = rel
            labels, tools = code_index(body)
            cleaned = clean_body(body)
            source_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
            qi = "\n".join(f"- `{l}`" for l in labels[:30]) or "- (no code blocks in this note)"
            if len(labels) > 30: qi += f"\n- … +{len(labels)-30} more (see body)"
            fm = (
                "---\n"
                f"technique: {json.dumps(title)}\n"
                f"family: {json.dumps(family)}\n"
                f"severity_hint: {json.dumps(sev)}\n"
                f"tags: {json.dumps(tags)}\n"
                f"source: {json.dumps('_raw/' + rel_clean)}\n"
                f"source_sha256: {json.dumps(source_sha256)}\n"
                f"curator_version: {CURATOR_VERSION}\n"
                "review_status: imported-unreviewed\n"
                "---\n\n"
            )
            doc = (
                fm +
                f"# {title}\n\n"
                f"> Family: **{family}** · Severity hint: **{sev}** · Tags: {', '.join(tags) or '—'}\n"
                f"> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: {', '.join(tools) or '—'}.\n\n"
                f"## Quick index — payloads & commands in this note\n{qi}\n\n"
                f"## Playbook (operator notes)\n\n{cleaned}\n\n"
                f"## Source\nOriginal note: `_raw/{rel_clean}`\n"
            )
            out = os.path.join(staged, slug + ".md")
            open(out, "w", encoding="utf-8").write(doc)
            rows.append((slug, rel_clean, title, family, sev, ",".join(tags), source_sha256, "imported-unreviewed"))
            catalog.setdefault(family, []).append((title, slug, sev, tags))

    # coverage manifest
    with open(os.path.join(staged, "_sources.tsv"), "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(("slug", "rawpath", "technique", "family", "severity", "tags", "source_sha256", "review_status"))
        for row in sorted(rows): writer.writerow(tuple(safe_tsv(value) for value in row))
    with open(os.path.join(staged, "_skipped.txt"), "w", encoding="utf-8") as f:
        for rel, why in skipped: f.write(f"{why}\t{rel}\n")

    # catalog
    SKILL_FAMILIES = {"injection","auth-session","http-protocol","ssrf-xxe-file","deserialization","client-side","access-control","agentic-ai"}
    with open(os.path.join(staged, "_catalog.md"), "w", encoding="utf-8") as f:
        f.write("# Web Playbook Catalog — signal → technique → playbook\n\n")
        f.write("Routing table for triage and hunters. Families with a dedicated hunting skill are marked ✅; "
                "others are reference playbooks the recon-agent / hunters consult opportunistically.\n\n")
        total = sum(len(v) for v in catalog.values())
        f.write(f"**{total} playbooks across {len(catalog)} families.**\n\n")
        for fam in sorted(catalog, key=lambda k: (k not in SKILL_FAMILIES, k)):
            mark = "✅ skill" if fam in SKILL_FAMILIES else "📄 reference"
            f.write(f"## {fam}  ({mark})  — {len(catalog[fam])} playbooks\n\n")
            f.write("| technique | severity | playbook | tags |\n|---|---|---|---|\n")
            for title, slug, sev, tags in sorted(catalog[fam]):
                f.write(f"| {safe_table(title)} | {sev} | `{slug}.md` | {safe_table(', '.join(tags[:5]))} |\n")
            f.write("\n")

    raw_count = sum(1 for root, _, files in os.walk(raw_root) for name in files if name.endswith(".md"))
    if raw_count != len(rows):
        raise RuntimeError(f"staged raw/manifest mismatch: raw={raw_count} rows={len(rows)}")
    missing = [slug for slug, *_ in rows if not os.path.isfile(os.path.join(staged, f"{slug}.md"))]
    if missing:
        raise RuntimeError(f"staged catalog targets missing: {missing[:10]}")
    replace_destination(staged, destination)

    print(f"curated={len(rows)}  skipped={len(skipped)}  families={len(catalog)}  curator_version={CURATOR_VERSION}")
    print("by family:", {k: len(v) for k, v in sorted(catalog.items())})
    if skipped: print("skipped:", skipped[:10])

if __name__ == "__main__":
    main()
