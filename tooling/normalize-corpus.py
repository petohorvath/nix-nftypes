#!/usr/bin/env python3
"""
normalize-corpus.py — flatten nftables' own test corpus into one JSON doc.

Corpus check in the channel-source pipeline (see docs/upstream-sync.md).
nftables ships a large regression corpus under `tests/py/**/*.t.json`: for
each rule the project tests, the exact libnftables-JSON `expr` array it expects. That
corpus is upstream telling us, version by version, what valid input looks
like — including constructs this library never thought to test. Running it
through our schema catches the "schema too restrictive" drift direction
(D2), which our own test suite structurally cannot: you can't write a test
for a field you don't know exists.

Each `.t.json` file is a sequence of records:

    # <rule text, as a title>
    [ <statement>, <statement>, … ]

    # <next rule text>
    [ … ]

This script walks the corpus, splits each file into records (records start
at a `# ` line; blank lines inside a JSON array are tolerated), parses the
JSON array, and emits a single JSON document to stdout:

    [ { "file": "...", "title": "...", "expr": [ … ] }, … ]

The Nix check (tests/upstream-corpus.nix) reads this and validates each
`expr` against `nftlib.types.statement`. Keeping the fragile text-splitting
in Python (one place, easy to unit-test) keeps the Nix side a clean
fromJSON + evalModules loop.

Usage:
    normalize-corpus.py <tests-py-dir>   > corpus.json
"""

import json
import os
import re
import sys


def records(text):
    """Yield (title, parsed_json_array) for each record in one .t.json file."""
    # Records start at a line beginning with "# ". Split *before* each such
    # line so a JSON array containing a blank line stays in one chunk.
    for chunk in re.split(r"\n(?=# )", text):
        chunk = chunk.strip()
        if not chunk.startswith("#"):
            continue
        title = chunk.splitlines()[0].lstrip("# ").rstrip()
        m = re.search(r"(\[.*\])", chunk, re.S)
        if not m:
            continue  # a comment-only record (e.g. a section header)
        try:
            payload = json.loads(m.group(1))
        except json.JSONDecodeError:
            # Some corpus payloads use placeholder tokens that aren't valid
            # JSON on their own; skip rather than abort the whole run.
            continue
        if isinstance(payload, list):
            yield title, payload


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    root = argv[1]
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".t.json"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            with open(path) as fh:
                for title, expr in records(fh.read()):
                    out.append({"file": rel, "title": title, "expr": expr})
    json.dump(out, sys.stdout, indent=0)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
