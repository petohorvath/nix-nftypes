#!/usr/bin/env python3
"""
extract-upstream-tokens.py — read the parser's enum and dispatch tokens
from the patched nftables source.

Token drift check in the nixpkgs-source pipeline (see
docs/upstream-sync.md). Extracts the accepted tokens of the cleanly
structured C tables in the selected package set's patched nftables source
tree: the primitive enums the JSON parser reads from a table, the ct keys
it takes a direction for, and the statement and expression dispatch
tables, and the keywords of nft's text lexer. The enum extraction suite
(tests/integration/nftables-enum-extraction.nix) compares each table with the
model's list; this script only reads the source. The byte units come from
`data_unit`, the table nft lists them from; the JSON parser's
`rate_to_bytes` reads the same names.

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
# entry has these keys:
#   "file"    the source file, relative to the tree root
#   "symbol"  the C symbol holding the table
#   "shape"   how its entries are written, one of the shapes below
#   "macro"   the template macro, for the "template" shape only
#   "member"  the struct member holding the token, for the "pair" and
#             "template" shapes; "designated" and "strings" take none
#   "resolve" for the "enumRefs" shape, the "template" table that
#             names each enum constant: its "file", "symbol", "macro",
#             and "member"; for the "protocols" shape, the "file" that
#             defines each protocol
#   "within"  optional: the function whose body holds the table, for a
#             local table whose name another function's table shares
#   "state"   for the "scannerKeywords" shape, the start condition whose
#             keywords to take, or None for those of every state
#   "floor"   the token count at the locked nixpkgs, so losing a single
#             entry fails the extraction
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
#   "template"      `[ENUM] = <macro>("name", …)`, or the expanded
#                   `[ENUM] = { ..., .token = "name" }`. (meta_templates,
#                   ct_templates)
#   "strings"       a string array, `{ "name", …, NULL }`: take each string
#                   literal. (data_unit)
#   "enumRefs"      an array of enum constants, `{ NFT_CT_SRC, … }`: take
#                   each constant's token from the "resolve" table, whose
#                   entries are indexed by the constants. (ct_dir_keys)
#   "protocols"     an array of protocol descriptions, `{ &proto_eth, … }`:
#                   take `<name> <field>` for each field of each protocol,
#                   its `.name` and the first string of each entry of its
#                   `.templates`, from the "resolve" file. (proto_tbl)
#   "scannerKeywords"
#                   the rules section of the flex scanner, between its two
#                   `%%` lines: with no "state", each identifier-shaped
#                   keyword of an unguarded rule, which every inclusive
#                   (`%s`) start condition shares, or of a `<*>` rule,
#                   which every one does; with a "state", each one a
#                   `<…,STATE,…>` rule or block guards. A rule that returns STRING is a name, not a
#                   keyword. (scanner.l)
REGISTRY = {
    "family": {
        "file": "src/parser_json.c",
        "symbol": "family_tbl",
        "shape": "pair",
        "member": "name",
        "floor": 6,
    },
    "rtKey": {
        "file": "src/parser_json.c",
        "symbol": "rt_key_tbl",
        "shape": "pair",
        "member": "name",
        "floor": 4,
    },
    "fibResult": {
        "file": "src/parser_json.c",
        "symbol": "fib_result_tbl",
        "shape": "designated",
        "floor": 4,
    },
    "metaKey": {
        "file": "src/meta.c",
        "symbol": "meta_templates",
        "shape": "template",
        "macro": "META_TEMPLATE",
        "member": "token",
        "floor": 37,
    },
    "ctKey": {
        "file": "src/ct.c",
        "symbol": "ct_templates",
        "shape": "template",
        "macro": "CT_TEMPLATE",
        "member": "token",
        "floor": 24,
    },
    # The ct keys json_parse_ct_expr takes a direction for: the enum
    # constants of ct_key_is_dir's local table, by their ct_templates token.
    "ctDirKey": {
        "file": "src/parser_json.c",
        "symbol": "ct_dir_keys",
        "shape": "enumRefs",
        "resolve": {
            "file": "src/ct.c",
            "symbol": "ct_templates",
            "macro": "CT_TEMPLATE",
            "member": "token",
        },
        "floor": 14,
    },
    # The byte units, which also check the model's limit rate units:
    # those add `packets`, which the parsers test for by name
    # (tests/helpers/token-drift.nix).
    "byteUnit": {
        "file": "src/statement.c",
        "symbol": "data_unit",
        "shape": "strings",
        "floor": 3,
    },
    # The two JSON dispatch tables: every statement / expression tag the
    # parser routes.
    "statementTag": {
        "file": "src/parser_json.c",
        "symbol": "stmt_parser_tbl",
        "shape": "pair",
        "member": "key",
        "floor": 35,
    },
    "expressionTag": {
        "file": "src/parser_json.c",
        "symbol": "cb_tbl",
        "shape": "pair",
        "member": "name",
        "floor": 34,
    },
    # The protocols a payload expression names, as `<protocol> <field>`:
    # proto_lookup_byname's local table, which json_parse_payload_expr
    # looks a protocol up in, and the fields json_parse_payload_field
    # looks up in each protocol's templates. inner_proto_lookup_byname has
    # a local table of the same name, for the tunnel form.
    "payloadField": {
        "file": "src/parser_json.c",
        "symbol": "proto_tbl",
        "within": "proto_lookup_byname",
        "shape": "protocols",
        "resolve": {"file": "src/proto.c"},
        "floor": 107,
    },
    # The text lexer's keywords, which nft reads as a keyword where the
    # text renderer writes a name, as `add set ip t counter`: those of
    # every state, then those of each state a name follows. A keyword
    # name fails to parse, quoted or not.
    "textKeyword": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": None,
        "floor": 161,
    },
    "textKeywordAt": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_AT",
        "floor": 2,
    },
    "textKeywordCounter": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_COUNTER",
        "floor": 3,
    },
    "textKeywordCt": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_CT",
        "floor": 25,
    },
    "textKeywordLimit": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_LIMIT",
        "floor": 9,
    },
    "textKeywordQuota": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_QUOTA",
        "floor": 5,
    },
    "textKeywordSynproxy": {
        "file": "src/scanner.l",
        "shape": "scannerKeywords",
        "state": "SCANSTATE_STMT_SYNPROXY",
        "floor": 7,
    },
}


def extract_block(text, symbol, within=None, pattern=r"\[[^\]]*\]\s*=\s*\{"):
    """Return the brace-delimited body of `<symbol>[…] = { … }` from `text`.

    With `within`, the table is the first one after the definition of the
    function `within`. `pattern` is what follows the symbol up to the
    opening brace. Brace-matches from the opening `{` so nested braces
    (struct entries) are handled. Raises if the table can't be found — a
    renamed/removed table is itself a drift signal worth surfacing loudly.
    """
    offset = 0
    if within:
        f = re.search(r"\b" + re.escape(within) + r"\s*\([^)]*\)\s*\{", text)
        if not f:
            raise LookupError(
                f"function '{within}' not found (renamed or removed upstream?)"
            )
        offset = f.end()
    m = re.compile(r"\b" + re.escape(symbol) + pattern).search(text, offset)
    if not m:
        raise LookupError(f"table '{symbol}' not found (renamed or removed upstream?)")
    return brace_body(text, m.end() - 1, symbol)


def brace_body(text, start, symbol):
    """Return the body of the brace block opening at `text[start]`."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    raise LookupError(f"unbalanced braces in table '{symbol}'")


def protocol_fields(text, symbol):
    """Return `<name> <field>` for each field of the proto_desc `symbol`."""
    body = extract_block(text, symbol, pattern=r"\s*=\s*\{")
    name = re.search(r'^\s*\.name\s*=\s*"([^"]*)"', body, re.MULTILINE)
    if not name:
        raise LookupError(f"protocol '{symbol}' has no .name")
    templates = re.search(r"\.templates\s*=\s*\{", body)
    if not templates:
        return []
    entries = brace_body(body, templates.end() - 1, f"{symbol}.templates")
    entry = re.compile(
        r'\[[^\]]*\]\s*=\s*(?:[A-Z][A-Z0-9_]*\(\s*"([^"]*)"|\{[^{}]*?'
        + designated_member("token")
        + r")"
    )
    return [
        f"{name.group(1)} {m.group(1) or m.group(2)}" for m in entry.finditer(entries)
    ]


def designated_member(member):
    return r"\." + re.escape(member) + r'\s*=\s*"([^"]*)"'


def template_tokens_by_index(block, spec):
    """Map each `[ENUM]` index of a "template" table to its token."""
    entry = re.compile(
        r"\[\s*([A-Z][A-Z0-9_]*)\s*\]\s*=\s*(?:"
        + re.escape(spec["macro"])
        + r'\(\s*"([^"]*)"|\{[^{}]*?'
        + designated_member(spec["member"])
        + r")"
    )
    return {m.group(1): m.group(2) or m.group(3) for m in entry.finditer(block)}


KEYWORD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


def scanner_keywords(rules, state):
    """Return the keywords of the scanner rules `rules` for `state`.

    `state` None takes the unguarded and `<*>` rules, which every
    inclusive start condition shares; a state name takes the rules a
    `<…>` prefix or block lists it in. A rule's keyword is its quoted pattern, when identifier-shaped and
    not returned as a STRING.
    """
    tokens = []
    block_states = None
    for line in rules.splitlines():
        if block_states is not None:
            if re.match(r"^\}\s*$", line):
                block_states = None
                continue
            m = re.match(r'^\s+"([^"]+)"\s+(.*)', line)
            if m and state in block_states:
                tokens.append((m.group(1), m.group(2)))
            continue
        m = re.match(r"^<([A-Z0-9_,*]+)>\{\s*$", line)
        if m:
            block_states = [None if s == "*" else s for s in m.group(1).split(",")]
            continue
        m = re.match(r'^<([A-Z0-9_,*]+)>"([^"]+)"\s+(.*)', line)
        if m:
            states = [None if s == "*" else s for s in m.group(1).split(",")]
            if state in states:
                tokens.append((m.group(2), m.group(3)))
            continue
        m = re.match(r'^"([^"]+)"\s+(.*)', line)
        if m and state is None:
            tokens.append((m.group(1), m.group(2)))
    return [
        token
        for token, action in tokens
        if KEYWORD.fullmatch(token) and "return STRING" not in action
    ]


def tokens_from_block(block, spec, read):
    shape = spec["shape"]
    if shape == "pair":
        # Each `{ … }` entry: its leading string, else its designated member.
        member = re.compile(designated_member(spec["member"]))
        tokens = []
        for entry in re.finditer(r"\{([^{}]*)\}", block):
            m = re.match(r'\s*"([^"]*)"', entry.group(1)) or member.search(
                entry.group(1)
            )
            if m:
                tokens.append(m.group(1))
        return tokens
    if shape == "designated":
        # RHS string of each `[ENUM] = "name"`; `= NULL` has no match.
        return [m.group(1) for m in re.finditer(r'=\s*"([^"]*)"', block)]
    if shape == "template":
        # First arg of each <macro>("name", …), or a `.token` member.
        pattern = (
            re.escape(spec["macro"])
            + r'\(\s*"([^"]*)"|'
            + designated_member(spec["member"])
        )
        return [m.group(1) or m.group(2) for m in re.finditer(pattern, block)]
    if shape == "strings":
        # Each string literal; the closing NULL has none.
        return re.findall(r'"([^"]*)"', block)
    if shape == "enumRefs":
        # Each enum constant, by the token its "resolve" table gives it.
        resolve = spec["resolve"]
        by_index = template_tokens_by_index(
            extract_block(read(resolve["file"]), resolve["symbol"]), resolve
        )
        tokens = []
        for constant in re.findall(r"\b([A-Z][A-Z0-9_]*)\b", block):
            if constant not in by_index:
                raise LookupError(
                    f"{spec['symbol']} names {constant}, which "
                    f"{resolve['symbol']} gives no token"
                )
            tokens.append(by_index[constant])
        return tokens
    if shape == "protocols":
        # Each `&proto_<x>`, by the fields its definition gives it.
        text = read(spec["resolve"]["file"])
        tokens = []
        for symbol in re.findall(r"&\s*([A-Za-z_][A-Za-z0-9_]*)", block):
            tokens.extend(protocol_fields(text, symbol))
        return tokens
    if shape == "scannerKeywords":
        return scanner_keywords(block, spec["state"])
    raise ValueError(f"unknown shape '{shape}'")


def rules_section(text, rel):
    """Return the rules section of the flex scanner `text`."""
    parts = re.split(r"^%%$", text, flags=re.MULTILINE)
    if len(parts) < 3:
        raise LookupError(f"{rel} has no rules section between two %% lines")
    return parts[1]


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
        if spec["shape"] == "scannerKeywords":
            block = rules_section(read(spec["file"]), spec["file"])
        else:
            block = extract_block(
                read(spec["file"]), spec["symbol"], spec.get("within")
            )
        # Filter empties (placeholder template slots) and dedupe, order-stable.
        tokens = list(
            dict.fromkeys(t for t in tokens_from_block(block, spec, read) if t)
        )
        if len(tokens) < spec["floor"]:
            raise LookupError(
                f"{spec.get('symbol', spec['file'])} yielded {len(tokens)} "
                f"token(s) for {name}, below its "
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
