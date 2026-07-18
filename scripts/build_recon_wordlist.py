#!/usr/bin/env python3
"""Build a bounded local recon wordlist from already-saved in-scope artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
AUTH_RE = re.compile(r"(?i)(?:authorization|cookie|password|token|secret|api[_-]?key)\s*[:=]\s*\S+")
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,63}")
STOPWORDS = {
    "authorization", "bearer", "cookie", "password", "passwd", "secret", "token",
    "username", "email", "owner", "href", "https", "http", "example", "test",
}
KNOWN_DIRS = ("admin", "api", "backup", "config", "uploads")
BACKUP_BASES = {"backup", "config", "database", "db", "settings"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _high_entropy(value: str) -> bool:
    if len(value) < 24:
        return False
    counts = Counter(value)
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
    return entropy >= 3.5 or (any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value))


def _acceptable(word: str, max_length: int) -> bool:
    lowered = word.lower().strip("-_")
    return (
        2 <= len(lowered) <= max_length
        and lowered not in STOPWORDS
        and not UUID_RE.fullmatch(lowered)
        and not JWT_RE.fullmatch(lowered)
        and not _high_entropy(lowered)
    )


def _extract(text: str, max_length: int) -> list[str]:
    ordered: list[str] = []
    urls = URL_RE.findall(text)
    for raw_url in urls:
        parsed = urlsplit(raw_url)
        for segment in unquote(parsed.path).split("/"):
            for token in TOKEN_RE.findall(segment):
                if _acceptable(token, max_length):
                    ordered.append(token.lower())
    scrubbed = URL_RE.sub(" ", text)
    for pattern in (EMAIL_RE, JWT_RE, UUID_RE, AUTH_RE):
        scrubbed = pattern.sub(" ", scrubbed)
    for token in TOKEN_RE.findall(scrubbed):
        if _acceptable(token, max_length):
            ordered.append(token.lower())
    return list(dict.fromkeys(ordered))


def build_wordlist(
    sources: list[Path], *, max_entries: int = 500, per_source: int = 100,
    max_token_length: int = 48,
) -> tuple[list[str], list[dict[str, object]]]:
    words: list[str] = []
    metadata: list[dict[str, object]] = []
    for source in sources:
        path = source.expanduser().resolve()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError(f"source must be a regular file no larger than 5 MiB: {source}")
        text = path.read_text(encoding="utf-8", errors="replace")
        extracted = _extract(text, max_token_length)[:per_source]
        metadata.append({"path": str(path), "sha256": sha256_file(path), "accepted": len(extracted)})
        for word in extracted:
            if word not in words and len(words) < max_entries:
                words.append(word)
    for base in list(words):
        if base in BACKUP_BASES:
            for suffix in (".bak", ".old", ".backup"):
                candidate = base + suffix
                if candidate not in words and len(words) < max_entries:
                    words.append(candidate)
    for directory in KNOWN_DIRS:
        if directory not in words and len(words) < max_entries:
            words.append(directory)
    return words[:max_entries], metadata


def write_wordlist(sources: list[Path], output: Path, **limits: int) -> Path:
    words, sources_meta = build_wordlist(sources, **limits)
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output.parent, 0o700)
    output.write_text("".join(f"{word}\n" for word in words), encoding="utf-8")
    os.chmod(output, 0o600)
    meta_path = output.with_suffix(output.suffix + ".meta.json")
    meta_path.write_text(json.dumps({
        "sources": sources_meta, "entries": len(words), "output_sha256": sha256_file(output),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(meta_path, 0o600)
    return meta_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-entries", type=int, default=500)
    parser.add_argument("--per-source", type=int, default=100)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        meta = write_wordlist(
            args.sources, args.output, max_entries=args.max_entries, per_source=args.per_source,
        )
    except (OSError, ValueError) as exc:
        print(f"wordlist build failed: {exc}")
        return 2
    print(f"wordlist={args.output} metadata={meta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
