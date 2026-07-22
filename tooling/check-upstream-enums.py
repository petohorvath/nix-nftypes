#!/usr/bin/env python3
"""
check-upstream-enums.py — deterministic enum + dispatch-tag drift detector.

Deterministic token check in the channel-source pipeline
(see docs/upstream-sync.md). Extracts accepted-token sets from the
cleanly-structured C tables in the selected channel package's patched nftables
source tree and diffs them against this library's schema: the
primitive enums (`nftlib.enums`) and the statement/expression tag unions
(the `attrTag` sets behind `types.statement` / `types.taggedExpression`).

This is the belt-and-suspenders complement to the AI watcher: where the AI
reads unstructured `strcmp` ladders, this script reads the well-formed C
tables with zero AI and zero false positives. It catches the historical
drift class recorded in docs/spec-coverage.md (G1 `rt key ipsec`, G3
`fib result check`), the highest-churn enum (`metaKey`), and — via the
dispatch tables — the "upstream added a whole new statement/expression
kind" class that would otherwise only surface if the corpus happened to
use it.

Usage:
    check-upstream-enums.py <nftables-source-root> <schema-tokens.json>

`schema-tokens.json` is produced by tests/upstream-enums.nix:

    {
      "enums":          { "<enum>": ["tok", ...], ... },   # nftlib.enums
      "statementTags":  ["accept", "match", ...],           # statement attrTag names
      "expressionTags": ["payload", "concat", ...]          # taggedExpression names
    }

Exit 0 if no drift; 1 if the parser accepts a token the schema rejects
(D2 drift — the dangerous, test-invisible direction); 3 on extraction
failure (renamed table, or a table whose token count fell below its
plausibility floor — refusing the vacuous green where a regex that no
longer matches reads as "no drift").

Only a *subset* of the schema's enums are source-table-backed and therefore
checkable here; the rest are parsed via `strcmp` ladders or live in other
files. The uncovered enums are listed explicitly in the report (no silent
caps) — they are the corpus check's and the AI watcher's job, not this
script's.
"""

import json
import re
import sys


# Registry: check name -> how to extract accepted tokens from the selected
# channel package's nftables source, and which schema token list to diff
# against. Each entry names the source file (relative to the tree root), the C
# symbol holding the table, its shape, and a `floor` (minimum plausible token
# count —
# extraction below it FAILS instead of passing vacuously; floors sit safely
# under today's counts: family 6, rtKey 4, fibResult 4, metaKey 37,
# stmt_parser_tbl 35, cb_tbl 41), an optional `target` (top-level key of the
# schema document; entries without one read `enums[<name>]`), and `fix` —
# where the token belongs when drift fires.
#
# Only tables that map 1:1 and unambiguously onto a schema token list are
# listed — `op_tbl` (bitwise operators; a slice of `cb_tbl`, which is
# covered) and the several same-named `flag_tbl[]` locals are deliberately
# excluded.
#
# Shapes:
#   "pair"          struct array `{ "name", ... }` — take the first string
#                   of each entry. (family_tbl, rt_key_tbl, stmt_parser_tbl,
#                   cb_tbl)
#   "designated"    `[ENUM] = "name"` designated initializers — take each RHS
#                   string literal; `= NULL` entries carry no string and are
#                   skipped. (fib_result_tbl)
#   "meta_template" `[ENUM] = META_TEMPLATE("name", …)` — take the first arg
#                   of each META_TEMPLATE(...) call. (meta_templates)
REGISTRY = {
    "family": {
        "file": "src/parser_json.c", "symbol": "family_tbl",
        "shape": "pair", "floor": 4,
        "fix": "lib/schema/primitives.nix",
    },
    "rtKey": {
        "file": "src/parser_json.c", "symbol": "rt_key_tbl",
        "shape": "pair", "floor": 3,
        "fix": "lib/schema/primitives.nix",
    },
    "fibResult": {
        "file": "src/parser_json.c", "symbol": "fib_result_tbl",
        "shape": "designated", "floor": 3,
        "fix": "lib/schema/primitives.nix",
    },
    "metaKey": {
        "file": "src/meta.c", "symbol": "meta_templates",
        "shape": "meta_template", "floor": 20,
        "fix": "lib/schema/primitives.nix",
    },
    # The two JSON dispatch tables: every statement / expression tag the
    # parser routes. Schema-only leftovers are expected and informational
    # (statements: `vmap` is dispatched outside the table, `xt` is modelled
    # but rejected by the parser — both documented in spec-coverage.md).
    "statementTag": {
        "file": "src/parser_json.c", "symbol": "stmt_parser_tbl",
        "shape": "pair", "floor": 20, "target": "statementTags",
        "fix": "lib/schema/statements.nix (statement attrTag union) + a lib/text renderer",
    },
    "expressionTag": {
        "file": "src/parser_json.c", "symbol": "cb_tbl",
        "shape": "pair", "floor": 20, "target": "expressionTags",
        "fix": "lib/schema/expressions.nix (taggedExpression union) + a lib/text renderer",
    },
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
        doc = json.load(fh)

    file_cache = {}

    def read(rel):
        if rel not in file_cache:
            with open(f"{src_root}/{rel}") as fh:
                file_cache[rel] = fh.read()
        return file_cache[rel]

    drift = {}   # check name -> tokens the parser accepts but the schema rejects
    report = []

    for name, spec in sorted(REGISTRY.items()):
        target = spec.get("target")
        schema_values = doc.get(target) if target else doc.get("enums", {}).get(name)
        if schema_values is None:
            drift[name] = [f"<'{target or name}' list absent from the schema document>"]
            continue
        try:
            block = extract_block(read(spec["file"]), spec["symbol"])
        except LookupError as exc:
            print(f"EXTRACTION FAILURE: {exc}", file=sys.stderr)
            return 3
        # Filter empties (placeholder template slots) and dedupe, order-stable.
        extracted = [t for t in tokens_from_block(block, spec["shape"]) if t]
        parser_set = dict.fromkeys(extracted)  # ordered set
        if len(parser_set) < spec["floor"]:
            print(
                f"EXTRACTION FAILURE: {spec['symbol']} yielded "
                f"{len(parser_set)} token(s), below the plausibility floor of "
                f"{spec['floor']} — the table shape likely changed and the "
                f"extractor no longer matches it. Refusing a vacuous pass.",
                file=sys.stderr,
            )
            return 3
        schema_set = set(schema_values)

        missing = [t for t in parser_set if t not in schema_set]   # DRIFT
        extra = [t for t in schema_values if t not in parser_set]  # info

        if missing:
            drift[name] = missing
        report.append(
            f"  {name:<14} parser={len(parser_set):<3} schema={len(schema_set):<3} "
            f"drift={missing or '-'} schema-only={extra or '-'} "
            f"[{spec['symbol']}]"
        )

    print("Upstream token extraction vs schema (enums + statement/expression tags)")
    print("(parser tokens missing from schema = drift; schema-only = info)\n")
    print("\n".join(report))
    print("\nNot source-checked (parsed via strcmp ladders / other files):")
    for enum, why in sorted(UNCHECKED_NOTES.items()):
        print(f"  {enum:<12} {why}")

    if drift:
        print("\nDRIFT DETECTED — the channel parser accepts tokens the schema rejects:")
        for name, toks in sorted(drift.items()):
            fix = REGISTRY.get(name, {}).get("fix", "lib/schema/primitives.nix")
            print(f"  {name}: add {toks} — {fix}")
        print(
            "\nThis is the test-invisible 'schema too restrictive' direction. "
            "Add the tokens, then record the gap in docs/spec-coverage.md."
        )
        return 1

    print("\nNo drift: every source-checked parser token is in the schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
