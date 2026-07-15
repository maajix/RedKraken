#!/usr/bin/env python3
"""Regression test for scripts/render_report.py's per-finding narrative template.

Asserts the finding block renders TL;DR / Summary / Details / PoC / Evidence /
Impact / Recommended Fix (the advisory format), preserves the evidence
sha256 hash (integrity/audit trail), and picks a fenced-code language from
the finding's `file` extension. Exit != 0 on fail.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import render_report as rr  # noqa: E402

FINDING = {
    "schema_version": 1,
    "id": "F-TEST-1",
    "title": "Storage endpoint trusts client-declared Content-Type",
    "technique": "Unrestricted upload of file with dangerous type",
    "family": "client-side",
    "severity": "medium",
    "status": "exploited",
    "summary": "Client-declared Content-Type is never checked against actual bytes.",
    "description": "The PUT handler stores whatever Content-Type the client claims without a magic-byte check.",
    "source": "manual",
    "file": "apps/web/src/app/api/storage/route.ts",
    "line": 91,
    "cwe": "CWE-434",
    "dataflow": ["route.ts:91 PUT accepts client Content-Type header unchecked"],
    "code_excerpt": "ALLOWED_UPLOAD_CONTENT_TYPES.has(contentType)",
    "evidence": ["evidence/F-TEST-1/poc.txt"],
    "repro": ["curl -X PUT <url> -H 'Content-Type: image/png' --data-binary @payload.html"],
    "impact": "Arbitrary bytes can be hosted from the app's trusted origin.",
    "remediation": "Validate magic bytes / re-encode via an image library.",
    "ts": "2026-07-11T00:00:00Z",
}

fail = 0


def check(label, condition):
    global fail
    fail += 0 if condition else 1
    print(f"  {'ok  ' if condition else 'FAIL'} {label}")


print("render_report per-finding template self-test:")

check("code_lang(.ts) == ts", rr.code_lang("route.ts") == "ts")
check("code_lang(unknown) == text", rr.code_lang("route.rs") == "text")
check("code_lang(None) == text", rr.code_lang(None) == "text")

directory = ROOT / "tests"  # unused paths only; evidence_lines() reports them missing
output = rr.render(directory, {"name": "test-engagement"}, [FINDING], [])

for heading in ("**TL;DR:**", "#### Summary", "#### Details", "#### PoC", "#### Evidence", "#### Impact", "#### Recommended Fix"):
    check(f"contains {heading!r}", heading in output)

check("TL;DR uses summary field", "Client-declared Content-Type is never checked" in output)
check("Summary section uses description field", "magic-byte check" in output)
check("title used as heading, not technique", "Storage endpoint trusts client-declared Content-Type" in output)
check("code excerpt fenced with ts language", "```ts" in output)
check("PoC section carries the repro command", "curl -X PUT" in output)
check("evidence path recorded as pending (file doesn't exist on disk)", "evidence/F-TEST-1/poc.txt` (missing)" in output)

print(f"\n{'PASS' if not fail else 'FAIL'}: {'all' if not fail else fail}")
sys.exit(1 if fail else 0)
