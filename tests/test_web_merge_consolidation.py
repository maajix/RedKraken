#!/usr/bin/env python3
"""Structural gate for reviewed imported-note consolidation.

Fixtures are repository metadata only.  No engagement, target, or evidence data is
read.  Each retired note must be absent and its retained destination must preserve
both curated-file and original-source provenance.
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "playbooks" / "web"

MERGES = {
    "api-rest.md": (
        "api.md",
        "52e419371f0c2e08352933d17d79d2a155c0b33f4afd412bbbbec0d4d1ae4340",
        "_raw/API/REST.md",
        "3f6bf3dfc08efeccb8806558ff03cca720f8d39fa220971933a4d3de1dc703db",
    ),
    "api-tools-kiterunner.md": (
        "api.md",
        "4b240828c726d0935c3305491729238adb090036fc10336a0809f1acb49125fe",
        "_raw/API/Tools/kiterunner.md",
        "928b5d1ec9b7fecfc589bf35866eafaaa2ec62ed57c5267cf27473d424d9ee40",
    ),
    "cms-cmsmap.md": (
        "_retired.md",
        "54374e9a31a06217d32371aff0675e505e156ce01d540f9f597b6e014deab7e8",
        "_raw/CMS/cmsmap.md",
        "4ad7490751566527e3f8640de8dbc83daf51fb1ffeb23f54681f8f59c65159d3",
    ),
    "prototype-pollution-clientside-pp.md": (
        "prototype-pollution.md",
        "bc53cb54a137a6f04489c847662a123b4fad2c7a81cbc87d55f44cb5cb6f3b72",
        "_raw/Web attacks/Web Attacks/Prototype Pollution/Clientside PP.md",
        "7eeb1d65bf23ad7ccbdfb4b12f52a96f9328aacc8d710bbf605c317af696d774",
    ),
    "sqli-file-read.md": (
        "sqli.md",
        "19c3b4f1b8131752debbd71d35588cd07f4cf97e705ca17a037d27586911c32d",
        "_raw/Web attacks/Web Attacks/SQLi/File Read.md",
        "8811d75832d36d170ca262d46bfca3296f84564a1ca0192094020a0cbf4ea517",
    ),
    "sqli-introduction-postgresql.md": (
        "sqli.md",
        "eff93fd4c2a4aac87a9a6fbf83714b850d8f7b14cf91344ad5023f40c06c6b00",
        "_raw/Web attacks/Web Attacks/SQLi/Introduction PostgreSQL.md",
        "5d691401b55ac3d922889d84edb0373360e3bedd916715ebf646c90f54743329",
    ),
    "sqli-mitigation.md": (
        "sqli.md",
        "12d7b35d9145846370453fb5e373994d6261078a4751e0aa00edc2699317546b",
        "_raw/Web attacks/Web Attacks/SQLi/Mitigation.md",
        "32ceff7b6c723f63ec0520c4a87998fd1bd627a16c58065a8e3801781cd1213a",
    ),
    "tabnabbing.md": (
        "clickjacking.md",
        "5ed744c04228da3e6b04d7ad6d1e287799c5d0850cfd40aeb79e51ebaf4a81a5",
        "_raw/Web attacks/Web Attacks/Tabnabbing.md",
        "d1a5d6040e5d7c0947690868d96fe0faf8252405a4e9a1a157b0692f5c80e619",
    ),
    "xss-paramspider.md": (
        "xss.md",
        "19bd58e5d628395f2535b845538baea7a80773e7d7edc38b1ef1e7007a4f410c",
        "_raw/Web attacks/Web Attacks/XSS/paramspider.md",
        "dd3f9a10c00e78087ec859ce3e9429bc916483a7afdc6e7ce4d026614f93bb6f",
    ),
}

EXPECTED_REVIEWED_SECTIONS = {
    "api.md": "## Reviewed consolidation — API discovery",
    "prototype-pollution.md": "## Reviewed consolidation — client-side gadget confirmation",
    "sqli.md": "## Reviewed consolidation — SQLi scope and remediation",
    "clickjacking.md": "## Reviewed consolidation — opener isolation",
    "xss.md": "## Reviewed consolidation — parameter discovery",
    "_retired.md": "## Retired imported notes",
}


class WebMergeConsolidationTest(unittest.TestCase):
    def test_sources_are_retired_with_complete_provenance(self) -> None:
        for source, (destination, curated_hash, raw_source, raw_hash) in MERGES.items():
            self.assertFalse((WEB / source).exists(), source)
            text = (WEB / destination).read_text(encoding="utf-8")
            for marker in (source, curated_hash, raw_source, raw_hash):
                self.assertIn(marker, text, f"{source} -> {destination}: {marker}")

    def test_destinations_mark_reviewed_safe_consolidation(self) -> None:
        for destination, heading in EXPECTED_REVIEWED_SECTIONS.items():
            self.assertIn(heading, (WEB / destination).read_text(encoding="utf-8"))

    def test_generated_indexes_drop_retired_slugs(self) -> None:
        catalog = (WEB / "_catalog.md").read_text(encoding="utf-8")
        sources = (WEB / "_sources.tsv").read_text(encoding="utf-8")
        for source in MERGES:
            slug = source.removesuffix(".md")
            self.assertNotIn(f"`{source}`", catalog)
            self.assertFalse(
                any(line.startswith(f"{slug}\t") for line in sources.splitlines()),
                slug,
            )


if __name__ == "__main__":
    unittest.main()
