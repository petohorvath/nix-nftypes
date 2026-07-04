#!/usr/bin/env python3
"""
check-upstream-enums.py — deterministic enum drift detector.

Layer 4 of the upstream-sync pipeline (see docs/upstream-sync.md). Extracts
the accepted-token sets from the cleanly-structured C tables in the *pinned*
nftables source tree and diffs them against this library's `nftlib.enums`.

This is the belt-and-suspenders complement to the AI watcher: where the AI
reads unstructured `strcmp` ladders, this script reads the well-formed C
tables with zero AI and zero false positives. It catches exactly the
historical drift class recorded in docs/spec-coverage.md (G1 `rt key ipsec`,
G3 `fib result check`) and the highest-churn enum, `metaKey`.

Usage:
    check-upstream-enums.py <nftables-src-root> <schema-enums.json>

`schema-enums.json` is `builtins.toJSON nftlib.enums` (a map of enum name →
list of accepted strings). Exit 0 if no drift, 1 if the parser accepts a
token the schema rejects (D2 drift — the dangerous, test-invisible direction).

Only a *subset* of the schema's enums are source-table-backed and therefore
checkable here; the rest are parsed via `strcmp` ladders or live in other
files. The uncovered enums are listed explicitly in the report (no silent
caps) — they are the AI watcher's job, not this script's.
"""

import json
import re
import sys


# Registry: schema-enum name -> how to extract its accepted tokens from the
# pinned nftables source. Each entry names the source file (relative to the
# tree root), the C symbol holding the table, and the table's shape. Only
# tables that map 1:1 and unambiguously onto a schema enum are listed —
# `op_tbl` (bitwise ops, not the relational `operator` enum) and the several
# same-named `flag_tbl[]` locals are deliberately excluded.
#
# Shapes:
#   "pair"          struct array `{ "name", VALUE }` — take the first string
#                   of each entry. (family_tbl, rt_key_tbl)
#   "designated"    `[ENUM] = "name"` designated initializers — take each RHS
#                   string literal; `= NULL` entries carry no string and are
#                   skipped. (fib_result_tbl)
#   "meta_template" `[ENUM] = META_TEMPLATE("name", …)` — take the first arg
#                   of each META_TEMPLATE(...) call. (meta_templates)
REGISTRY = {
    "family":    {"file": "src/parser_json.c", "symbol": "family_tbl",      "shape": "pair"},
    "rtKey":     {"file": "src/parser_json.c", "symbol": "rt_key_tbl",      "shape": "pair"},
    "fibResult": {"file": "src/parser_json.c", "symbol": "fib_result_tbl",  "shape": "designated"},
    "metaKey":   {"file": "src/meta.c",        "symbol": "meta_templates",  "shape": "meta_template"},
}

# Enums known to come from `strcmp` ladders or non-table sources — reported as
# "not source-checked" so coverage is never silently overstated. Not
# exhaustive of every schema enum; it documents the notable uncheckable ones.
UNCHECKED_NOTES = {
    "operator":  "relational ops parsed inline, not via a named table",
    "socketKey": "strcmp ladder in json_parse_socket_expr",
    "osfKey":    "strcmp branches in json_parse_osf_expr (G2 was here)",
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
    raise ValueError(f"unbalanced braces in table '{symbol}'")


def tokens_from_block(block, shape):
    if shape == "pair":
        # First quoted string of each `{ "name", VALUE }` entry.
        return [m.group(1) for m in re.finditer(r'\{\s*"([^"]*)"', block)]
    if shape == "designated":
        # RHS string of each `[ENUM] = "name"`; `= NULL` has no match.
        return [m.group(1) for m in re.finditer(r'=\s*"([^"]*)"', block)]
    if shape == "meta_template":
        # First arg of each META_TEMPLATE("name", …).
        return [m.group(1) for m in re.finditer(r'META_TEMPLATE\(\s*"([^"]*)"', block)]
    raise ValueError(f"unknown shape '{shape}'")


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    src_root, schema_path = argv[1], argv[2]

    with open(schema_path) as fh:
        schema = json.load(fh)

    file_cache = {}

    def read(rel):
        if rel not in file_cache:
            with open(f"{src_root}/{rel}") as fh:
                file_cache[rel] = fh.read()
        return file_cache[rel]

    drift = {}   # enum -> tokens the parser accepts but the schema rejects
    report = []

    for enum, spec in sorted(REGISTRY.items()):
        if enum not in schema:
            drift[enum] = ["<enum absent from nftlib.enums entirely>"]
            continue
        block = extract_block(read(spec["file"]), spec["symbol"])
        # Filter empties (placeholder template slots) and dedupe, order-stable.
        extracted = [t for t in tokens_from_block(block, spec["shape"]) if t]
        parser_set = dict.fromkeys(extracted)  # ordered set
        schema_set = set(schema[enum])

        missing = [t for t in parser_set if t not in schema_set]   # DRIFT
        extra = [t for t in schema[enum] if t not in parser_set]    # info

        if missing:
            drift[enum] = missing
        report.append(
            f"  {enum:<12} parser={len(parser_set):<3} schema={len(schema_set):<3} "
            f"drift={missing or '-'} schema-only={extra or '-'} "
            f"[{spec['symbol']}]"
        )

    print("Upstream enum extraction vs nftlib.enums")
    print("(parser tokens missing from schema = drift; schema-only = info)\n")
    print("\n".join(report))
    print("\nNot source-checked (parsed via strcmp ladders / other files):")
    for enum, why in sorted(UNCHECKED_NOTES.items()):
        print(f"  {enum:<12} {why}")

    if drift:
        print("\nDRIFT DETECTED — the pinned parser accepts tokens the schema rejects:")
        for enum, toks in sorted(drift.items()):
            print(f"  {enum}: add {toks} to lib/schema/primitives.nix")
        print(
            "\nThis is the test-invisible 'schema too restrictive' direction. "
            "Add the tokens, then record the gap in docs/spec-coverage.md."
        )
        return 1

    print("\nNo enum drift: every source-checked parser token is in the schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
