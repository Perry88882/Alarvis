#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write checksums/SHA256SUMS.txt for every tracked file.

Usage (from the repository root):
    python3 code/make_checksums.py

Excludes generated output (recompute_out/), Python caches, and the checksum
manifest itself.  Format: "<sha256>  <relative/path>".
"""

import hashlib
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_DIR = os.path.join(ROOT, "checksums")
OUT = os.path.join(OUT_DIR, "SHA256SUMS.txt")
SKIP_DIRS = {"recompute_out", "__pycache__", ".git", "checksums"}
SKIP_FILES = {".DS_Store", "Thumbs.db"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    entries = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in SKIP_FILES or name.endswith(".pyc"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            if rel == "checksums/SHA256SUMS.txt":
                continue
            entries.append((rel, sha256(path)))
    entries.sort()
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for rel, digest in entries:
            f.write("%s  %s\n" % (digest, rel))
    print("wrote %s (%d files)" % (os.path.relpath(OUT, ROOT), len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
