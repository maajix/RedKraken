#!/usr/bin/env python3
"""Normalize engagement permissions without following symbolic links."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from harness_config import ConfigError, engagement_yaml


def secure_engagement(directory: Path) -> tuple[int, int, list[str]]:
    root = directory.resolve()
    root.chmod(0o700)
    directories = 1
    files = 0
    warnings: list[str] = []
    for name in ("engagement.yaml", "audit.jsonl", "report.md"):
        path = root / name
        if path.is_symlink():
            warnings.append(f"skipped symbolic link: {path}")
        elif path.is_file():
            path.chmod(0o600)
            files += 1
    for name in ("state", "evidence"):
        subtree = root / name
        if not subtree.exists():
            continue
        if subtree.is_symlink():
            warnings.append(f"skipped symbolic link: {subtree}")
            continue
        for current, dirnames, filenames in os.walk(subtree, followlinks=False):
            current_path = Path(current)
            current_path.chmod(0o700)
            directories += 1
            for dirname in list(dirnames):
                path = current_path / dirname
                if path.is_symlink():
                    warnings.append(f"skipped symbolic link: {path}")
                    dirnames.remove(dirname)
            for filename in filenames:
                path = current_path / filename
                if path.is_symlink():
                    warnings.append(f"skipped symbolic link: {path}")
                    continue
                if path.is_file():
                    path.chmod(0o600)
                    files += 1
    return directories, files, warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engagement")
    args = parser.parse_args()
    try:
        yaml_path = engagement_yaml(args.engagement)
        directories, files, warnings = secure_engagement(yaml_path.parent)
        for warning in warnings:
            print(f"WARNING: {warning}")
        print(f"secured_directories={directories} secured_files={files} skipped_links={len(warnings)}")
        return 0
    except (ConfigError, OSError) as exc:
        print(f"secure_engagement: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
