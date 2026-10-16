#!/usr/bin/env python3
"""
extract-upstream-tokens.py — read the parser's enum and dispatch tokens
from the patched nftables source.

Token drift check in the nixpkgs-source pipeline (see
docs/upstream-sync.md). Extracts the accepted tokens of the cleanly
structured C tables in the selected package set's patched nftables source
tree: the primitive enums the JSON parser reads from a table, and the
statement and expression dispatch tables. The enum extraction suite
(tests/integration/nftables-enum-extraction.nix) compares each table with the
model's list; this script only reads the source.

Unstructured `strcmp` ladders (`operator`, `socketKey`, `osfKey`) are out
of its reach; they are left to the corpus check and to the maintainer
reviewing a Drift issue's source diff.

Usage:
    extract-upstream-tokens.py <nftables-source-root>   > tokens.json

Prints `{ "<table>": ["tok", ...], ... }` and exits 0. Exits 3 on an
extraction failure: a table that is missing (renamed or removed), or one
that yields fewer tokens than its floor. A regex that no longer matches
would otherwise read as a table that shrank.
"""

import json
import re
import sys


# Registry: table name -> how to extract its tokens from the source. Each
# entry names the source file (relative to the tree root), the C symbol
# holding the table, its shape, the struct member holding the token, and
# a `floor`: the token count at the locked nixpkgs, so losing a single
# entry fails the extraction.
#
# Only tables that map 1:1 and unambiguously onto a model token list are
# listed: `op_tbl` (bitwise operators; a slice of `cb_tbl`, which is
# covered) and the several same-named `flag_tbl[]` locals are deliberately
# excluded.
#
# Shapes:
#   "pair"          struct array: take each entry's token, either its
#                   first string `{ "name", ... }` or its designated
#                   member `{ ..., .name = "name" }`. (family_tbl,
#                   rt_key_tbl, stmt_parser_tbl, cb_tbl)
#   "designated"    `[ENUM] = "name"` designated initializers — take each RHS
#                   string literal; `= NULL` entries carry no string and are
#                   skipped. (fib_result_tbl)
#   "meta_template" `[ENUM] = META_TEMPLATE("name", …)`, or the expanded
#                   `[ENUM] = { ..., .token = "name" }`. (meta_templates)
REGISTRY = {
    "family": {
        "file": "src/parser_json.c", "symbol": "family_tbl",
        "shape": "pair", "member": "name", "floor": 6,
    },
    "rtKey": {
        "file": "src/parser_json.c", "symbol": "rt_key_tbl",
        "shape": "pair", "member": "name", "floor": 4,
    },
    "fibResult": {
        "file": "src/parser_json.c", "symbol": "fib_result_tbl",
        "shape": "designated", "floor": 4,
    },
    "metaKey": {
        "file": "src/meta.c", "symbol": "meta_templates",
        "shape": "meta_template", "member": "token", "floor": 37,
    },
    # The two JSON dispatch tables: every statement / expression tag the
    # parser routes.
    "statementTag": {
        "file": "src/parser_json.c", "symbol": "stmt_parser_tbl",
        "shape": "pair", "member": "key", "floor": 35,
    },
    "expressionTag": {
        "file": "src/parser_json.c", "symbol": "cb_tbl",
        "shape": "pair", "member": "name", "floor": 34,
    },
}


def extract_block(text, symbol):
    """Return the brace-delimited body of `<symbol>[] = { … }` from `text`.

    Brace-matches from the opening `{` so nested braces (struct entries) are
    handled. Raises if the table can't be found — a renamed/removed table is
    itself a drift signal worth surfacing loudly.
    """
    m = re.search(re.escape(symbol) + r"\[\]\s*=\s*\{", text)
    if not m:
        raise LookupError(f"table '{symbol}' not found (renamed or removed upstream?)")
    start = m.end() - 1  # position of the opening brace
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    raise LookupError(f"unbalanced braces in table '{symbol}'")


def designated_member(member):
    return r"\." + re.escape(member) + r'\s*=\s*"([^"]*)"'


def tokens_from_block(block, spec):
    shape = spec["shape"]
    if shape == "pair":
        # Each `{ … }` entry: its leading string, else its designated member.
        member = re.compile(designated_member(spec["member"]))
        tokens = []
        for entry in re.finditer(r"\{([^{}]*)\}", block):
            m = re.match(r'\s*"([^"]*)"', entry.group(1)) or member.search(entry.group(1))
            if m:
                tokens.append(m.group(1))
        return tokens
    if shape == "designated":
        # RHS string of each `[ENUM] = "name"`; `= NULL` has no match.
        return [m.group(1) for m in re.finditer(r'=\s*"([^"]*)"', block)]
    if shape == "meta_template":
        # First arg of each META_TEMPLATE("name", …), or a `.token` member.
        pattern = r'META_TEMPLATE\(\s*"([^"]*)"|' + designated_member(spec["member"])
        return [m.group(1) or m.group(2) for m in re.finditer(pattern, block)]
    raise ValueError(f"unknown shape '{shape}'")


def extract(src_root):
    """Return `{ table: [token, ...] }`; raises LookupError on a failure."""
    file_cache = {}

    def read(rel):
        if rel not in file_cache:
            with open(f"{src_root}/{rel}") as fh:
                file_cache[rel] = fh.read()
        return file_cache[rel]

    tables = {}
    for name, spec in sorted(REGISTRY.items()):
        block = extract_block(read(spec["file"]), spec["symbol"])
        # Filter empties (placeholder template slots) and dedupe, order-stable.
        tokens = list(dict.fromkeys(t for t in tokens_from_block(block, spec) if t))
        if len(tokens) < spec["floor"]:
            raise LookupError(
                f"{spec['symbol']} yielded {len(tokens)} token(s), below its "
                f"floor of {spec['floor']}: an entry was removed, or the "
                f"table shape changed and the extractor no longer reads it."
            )
        tables[name] = tokens
    return tables


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        tables = extract(argv[1])
    except LookupError as exc:
        print(f"EXTRACTION FAILURE: {exc}", file=sys.stderr)
        return 3
    json.dump(tables, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
