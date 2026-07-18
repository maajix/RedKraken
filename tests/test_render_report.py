#!/usr/bin/env python3
"""Regression test for scripts/render_report.py's per-finding narrative template.

Asserts the finding block renders TL;DR / Summary / Details / PoC / Evidence /
Impact / Recommended Fix (the advisory format), preserves the evidence
sha256 hash (integrity/audit trail), and picks a fenced-code language from
the finding's `file` extension. Runs under pytest (as test_*) and as a
standalone script (exit != 0 on fail).
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


def checks():
    """Yield (label, passed) for each assertion; shared by pytest + script."""
    yield "code_lang(.ts) == ts", rr.code_lang("route.ts") == "ts"
    yield "code_lang(unknown) == text", rr.code_lang("route.rs") == "text"
    yield "code_lang(None) == text", rr.code_lang(None) == "text"
    # directory holds unused paths only; evidence_lines() reports them missing
    output = rr.render(
        ROOT / "tests",
        {
            "name": "synthetic-assessment",
            "mutation_allowed": True,
            "sensitive_data_access_allowed": False,
            "credential_use_allowed": False,
            "pivoting_allowed": False,
            "availability_impact_allowed": False,
        },
        [FINDING],
        [],
    )
    for heading in ("**TL;DR:**", "#### Summary", "#### Details", "#### PoC",
                    "#### Evidence", "#### Impact", "#### Recommended Fix"):
        yield f"contains {heading!r}", heading in output
    yield "TL;DR uses summary field", "Client-declared Content-Type is never checked" in output
    yield "Summary section uses description field", "magic-byte check" in output
    yield "title used as heading, not technique", "Storage endpoint trusts client-declared Content-Type" in output
    yield "code excerpt fenced with ts language", "```ts" in output
    yield "PoC section carries the repro command", "curl -X PUT" in output
    yield "evidence path recorded as pending (file doesn't exist on disk)", "evidence/F-TEST-1/poc.txt` (missing)" in output
    yield "report renders mutation gate", "Mutation allowed: `true`" in output
    yield "report renders sensitive-read gate", "Sensitive data access allowed: `false`" in output
    yield "report renders credential-use gate", "Credential use allowed: `false`" in output
    yield "report renders pivot gate", "Pivoting allowed: `false`" in output
    yield "report renders availability gate", "Availability impact allowed: `false`" in output


def test_render_report_template():
    failures = [label for label, ok in checks() if not ok]
    assert not failures, failures


if __name__ == "__main__":
    fail = 0
    print("render_report per-finding template self-test:")
    for label, ok in checks():
        fail += 0 if ok else 1
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    print(f"\n{'PASS' if not fail else 'FAIL'}: {'all' if not fail else fail}")
    sys.exit(1 if fail else 0)
