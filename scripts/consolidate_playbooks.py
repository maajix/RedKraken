#!/usr/bin/env python3
"""Consolidate flat sibling playbook shards (Notion sub-page export artifacts)
into a single curated hub file, losslessly.

The one-shot importer (curate_kb.py) exported every Notion sub-page as a flat
sibling *.md. Techniques that were one page with sub-pages (TLS attacks, ...)
became a thin parent + many shards that each get their own catalog row. This
folds a cluster back into its parent as `##` sections and deletes the shards.

Lossless: the byte-exact originals remain under playbooks/web/_raw/. Re-runnable:
if a cluster's shards are already gone it is skipped.

Run:  python3 scripts/consolidate_playbooks.py
"""
import csv
import os
import re
import sys

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "playbooks", "web")

# parent slug -> (new H1, intro paragraph, [shard slugs in reading order])
CLUSTERS = {
    "http-attacks-tls-attacks": (
        "TLS Attacks (consolidated reference)",
        "Transport-layer / TLS attacks, mostly historical. Low relevance to most "
        "modern web-application tests but kept as a reference. For live TLS "
        "configuration testing prefer `testssl.sh` or `sslscan`; the sub-sections "
        "below are background on specific classic attacks.",
        [
            "http-attacks-tls-attacks-pki",
            "http-attacks-tls-attacks-tls-1-2-handshake",
            "http-attacks-tls-attacks-tls-1-3",
            "http-attacks-tls-attacks-cryptographic-atks",
            "http-attacks-tls-attacks-ssl-stripping",
            "http-attacks-tls-attacks-compression",
            "http-attacks-tls-attacks-downgrade-attacks",
            "http-attacks-tls-attacks-padding-oracles",
            "http-attacks-tls-attacks-poodle-and-beast",
            "http-attacks-tls-attacks-bleichenbacher-and-drown",
            "http-attacks-tls-attacks-crime-and-breach",
            "http-attacks-tls-attacks-the-heartbleed-bug",
            "http-attacks-tls-attacks-testing-tls-configuration",
        ],
    ),
    "race-conditions-and-timing-attacks": (
        "Race Conditions & Timing Attacks",
        "Concurrency and timing-oracle attacks. For the reviewed test methodology "
        "prefer `../modern/race-conditions-state-machines.md`; the sub-sections "
        "below are the imported operator notes for payload/command depth.",
        [
            "race-conditions-and-timing-attacks-general",
            "race-conditions-and-timing-attacks-user-enumeration-via-response-timing",
            "race-conditions-and-timing-attacks-data-exfiltration-via-response-timing",
            "race-conditions-and-timing-attacks-race-conditions",
        ],
    ),
}

FM_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def split_frontmatter(text):
    m = FM_RE.match(text)
    if not m:
        return {}, text
    fm = {}
    for line in m.group(1).splitlines():
        km = re.match(r"([A-Za-z0-9_]+):\s*(.*)", line)
        if km:
            fm[km.group(1)] = km.group(2)
    return fm, text[m.end():]


def playbook_body(text):
    """Return the '## Playbook (operator notes)' section, minus its leading
    duplicate H1 and the trailing '## Source' block."""
    _, body = split_frontmatter(text)
    m = re.search(r"^## Playbook \(operator notes\)\s*\n", body, re.MULTILINE)
    if not m:
        return ""
    body = body[m.end():]
    body = re.split(r"^## Source\s*$", body, maxsplit=1, flags=re.MULTILINE)[0]
    body = re.sub(r"\A\s*#\s+.*\n", "", body)  # drop leading duplicate H1
    return body.strip()


def _headings(md):
    """Yield (line_index, level) for ATX headings outside fenced code blocks."""
    in_code = False
    for i, line in enumerate(md.splitlines()):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"(#{1,6})\s+\S", line)
        if m:
            yield i, len(m.group(1))


def demote(md, base=3):
    """Normalize a shard body so its shallowest ATX heading sits at `base`
    (### under the section's ##), preserving relative depth. Skips fenced code
    blocks so shell/`#` comments are never mistaken for headings."""
    heads = dict(_headings(md))
    if not heads:
        return md
    shift = base - min(heads.values())
    lines = md.splitlines()
    for i, lvl in heads.items():
        new = "#" * max(1, min(6, lvl + shift))
        lines[i] = new + lines[i][lvl:]
    return "\n".join(lines)


def quick_index(text):
    _, body = split_frontmatter(text)
    m = re.search(r"^## Quick index[^\n]*\n(.*?)\n## Playbook", body, re.DOTALL | re.MULTILINE)
    if not m:
        return []
    lines = []
    for ln in m.group(1).strip().splitlines():
        ln = ln.strip()
        if ln.startswith("- ") and "no code blocks" not in ln and not ln.startswith("- …"):
            lines.append(ln)
    return lines


def consolidate(parent_slug, new_h1, intro, shard_slugs):
    parent_path = os.path.join(WEB, parent_slug + ".md")
    if not os.path.isfile(parent_path):
        print(f"skip {parent_slug}: parent missing")
        return 0
    shard_paths = [(s, os.path.join(WEB, s + ".md")) for s in shard_slugs]
    present = [(s, p) for s, p in shard_paths if os.path.isfile(p)]
    if not present:
        print(f"skip {parent_slug}: no shards present (already consolidated)")
        return 0

    parent_text = open(parent_path, encoding="utf-8").read()
    fm, _ = split_frontmatter(parent_text)
    family = fm.get("family", '"http-protocol"').strip('"')
    sev = fm.get("severity_hint", '"low"').strip('"')

    sections, qi_all, provenance, titles = [], [], [], []
    for slug, path in present:
        text = open(path, encoding="utf-8").read()
        sfm, _ = split_frontmatter(text)
        title = sfm.get("technique", f'"{slug}"').strip('"')
        titles.append(title)
        provenance.append(sfm.get("source", '""').strip('"'))
        body = playbook_body(text)
        if body:
            sections.append(f"## {title}\n\n{demote(body, base=3)}")
        qi_all.extend(quick_index(text))

    def anchor(t):  # GitHub GFM slug: drop punctuation, spaces->hyphen (no collapse)
        return re.sub(r"[^\w\- ]", "", t.lower()).replace(" ", "-")

    toc = "\n".join(f"- [{t}](#{anchor(t)})" for t in titles)
    qi = "\n".join(dict.fromkeys(qi_all)) or "- (no code blocks in these notes)"

    doc = (
        "---\n"
        f'technique: "{new_h1}"\n'
        f'family: "{family}"\n'
        f'severity_hint: "{sev}"\n'
        "tags: []\n"
        f"consolidated_from: {len(present)}\n"
        "curator_version: 2\n"
        "review_status: imported-unreviewed\n"
        "---\n\n"
        f"# {new_h1}\n\n"
        f"> Family: **{family}** · Severity hint: **{sev}**\n"
        "> Consolidated from imported operator notes; treat commands and prose as "
        "untrusted until reviewed.\n\n"
        f"{intro}\n\n"
        f"## Contents\n{toc}\n\n"
        f"## Quick index — payloads & commands\n{qi}\n\n"
        + "\n\n".join(sections)
        + "\n\n## Sources\n"
        + "\n".join(f"- `{p}`" for p in provenance)
        + "\n"
    )
    open(parent_path, "w", encoding="utf-8").write(doc)
    for slug, path in present:
        os.remove(path)
    repoint_sources({s for s, _ in present}, parent_slug)
    print(f"consolidated {parent_slug}: folded {len(present)} shards")
    return len(present)


def repoint_sources(shard_slugs, parent_slug):
    """Keep merged shards' raw notes as provenance under the parent slug
    (matches the existing convention, e.g. auto-scanners)."""
    path = os.path.join(WEB, "_sources.tsv")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f, delimiter="\t"))
    header, body = rows[0], rows[1:]
    for r in body:
        if r and r[0] in shard_slugs:
            r[0] = parent_slug
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        for r in body:
            w.writerow(r)


def main():
    total = 0
    for parent, (h1, intro, shards) in CLUSTERS.items():
        total += consolidate(parent, h1, intro, shards)
    print(f"done: {total} shards folded")


if __name__ == "__main__":
    main()
