# Schema coverage

This document states what `lib/schema/` models, what evidence checks it, and
where it intentionally differs from nftables. It is a current-state reference,
not a history of earlier fixes.

## Compatibility authority

The authorities are the nftables packages in the two locked flake inputs:

- stable `nixpkgs`;
- `nixpkgs-unstable`.

For each channel, source checks use `pkgs.nftables.src` plus the derivation's
complete downstream patch set. Live checks use that same channel's `nft`
binary. There is no independent Netfilter Git input.

The parser (`src/parser_json.c`) defines accepted JSON input. The serializer
(`src/json.c`) defines read-back shapes. The libnftables JSON manual is useful
reference material but is not complete enough to be the sole authority.

## Modelled surfaces

| Surface | Current schema |
| --- | --- |
| Commands | `add`, `replace`, `create`, `insert`, `delete`, `destroy`, `list`, `reset`, `flush`, `rename` |
| Add objects | 16 singular object kinds |
| Create objects | 15 kinds; `rule` is excluded because nftables rejects `create rule` |
| List objects | 16 add objects plus `metainfo` and `meter` |
| Flush objects | table, chain, set, map, meter, ruleset |
| Reset objects | counter, quota, rule, set, map, element |
| Statements | 37 tagged forms |
| Tagged expressions | 34 tags, plus scalar and bare-list branches in the full `expression` type |

The schema also includes parser behavior missing or incomplete in the manual,
including:

- `last`, `flow`, `tproxy`, `reset`, `secmark`, and `tunnel` statements;
- `secmark`, `synproxy`, and tunnel objects;
- inner-header payloads, raw TCP option forms, tunnel payloads, and XFRM/tunnel
  metadata expressions;
- parser-only enum values such as `rt.ipsec`, `fib.check`, and OS fingerprint
  `version`;
- list-or-singleton device fields and stateful statements attached to set/map
  elements;
- nullable handles and other serializer fields needed by selected read-back
  cases.

## Known differences

“Schema coverage” does not mean byte-for-byte equivalence with every parser
branch. Differences fall into four groups.

### 1. Parser input accepted but schema rejected

The packaged nftables statement corpus currently exercises 11 baselined
categories:

| Category | Schema limitation |
| --- | --- |
| five null-body forms | bare `reject`, `redirect`, `masquerade`, `log`, and `queue` statements require object bodies in the schema |
| unary negation | match operator `!` is not in the operator enum |
| four mapped stateful objects | `counter map`, `quota map`, `limit map`, and `synproxy map` are not represented |
| partial synproxy | a flags-only synproxy statement is rejected because the schema requires `mss` and `wscale` together |

The executable baseline is `knownDivergences` in
[`tests/upstream-corpus.nix`](../tests/upstream-corpus.nix). A statement matching
no known category fails the check. Categories that disappear are reported as
stale so the baseline can shrink.

Additional command and selector differences are not statement-corpus shapes:

- nftables has plural `list` selector forms such as `tables`, `chains`, and
  `sets`, plus plural `reset` selector forms; these parser-accepted command
  forms are not modelled;
- several command verbs accept slimmer selector bodies than the schema's
  shared object bodies. For example, the parser's delete-rule path selects by
  family/table/chain/handle, while the shared schema body still includes
  `expr`;
- delete-by-handle variants for some object kinds are not represented exactly.

Use direct JSON only when one of these parser forms is required, and validate
it with the real channel parser.

### 2. Schema intentionally more permissive

Some parser conditions depend on large lookup tables or relationships between
fields. The schema checks useful local types but leaves the final condition to
`nft`:

- `ct.key` is a string, and whether `ct.dir` is legal depends on that key;
- FIB flags have parser-level mutual-exclusion rules;
- tunnel source and destination fields must form one same-family pair;
- set/map datatypes and several unit names are strings rather than exhaustive
  enums;
- `flow.flowtable` does not enforce the parser-required `@` reference prefix;
- `mangle.key` and the `reset` statement accept broader expression shapes than
  the parser, while `concat` does not enforce its minimum of two operands;
- tunnel `type` and its nested tunnel-parameter body are typed independently,
  so agreement between them remains a parser check;
- some NAT, reject, and object-field combinations are meaningful only in
  specific contexts.

A schema-successful value is therefore not proof that a particular kernel will
accept the resulting ruleset. Live-parser and real-load tests remain necessary.

### 3. Read-back/input asymmetries

`xt` is modelled because listed legacy rules can contain it, but the JSON parser
rejects `xt` as new input and instructs callers to use `iptables-nft`.

Handles and metadata emitted by `nft -j list ruleset` are accepted where the
current body model needs them. The top-level ruleset union accepts both command
wrappers and bare listed objects. This does not imply that every possible
serializer output has been observed.

### 4. JSON and text are separate surfaces

A schema value can be valid JSON input while lacking a usable text spelling.
Text support and exclusions are tracked separately in
[`text-coverage.md`](text-coverage.md).

## Validation boundaries

Nix module validation is strict about declared fields, enum membership, and
primitive types. It is applied when callers use `nftlib.types` or when the DSL
expands its own structured nodes.

The renderers do not run arbitrary raw values through `types.ruleset`.
Likewise, raw attrsets inserted into `dsl.ruleset` are escape hatches and are
passed through. See [`api.md`](api.md) for an explicit `evalModules` example.

## Executable evidence

| Check | What it proves | Important limit |
| --- | --- | --- |
| `schema-tests` and focused safety suites | Nix-level accepted/rejected values and renderer regressions | hand-written cases cannot discover unknown upstream syntax |
| `integration-tests` | selected JSON renderings pass the channel's `nft -c -j -f`, and a raw `create rule` parser-negative case is rejected | selected cases only; check mode is not a real load |
| `nftables-source-provenance-tests` | source analysis uses the selected package source and patches | provenance, not semantic coverage |
| `nftables-enum-extraction-tests` | extracted parser tokens/tags match schema lists and plausibility floors | extractor covers enumerated patterns, not every conditional branch |
| `nftables-corpus-tests` | upstream statement corpus has no unclassified schema rejection | 11 categories are explicitly baselined |
| `nftables-roundtrip-tests` | every command emitted by nine real-loaded selected cases validates as `types.ruleset` | two cases are explicitly excluded; it is sampled serializer coverage |
| `nftables-tooling-selftests` | injected source/corpus/token defects make the drift checks fail | tests the tooling's chosen fault classes |

All channel-dependent checks are instantiated separately for locked stable and
unstable package sets on each Linux check system.

## Updating the schema

For a confirmed parser or serializer change:

1. inspect the exact patched source from the affected nixpkgs input;
2. add a failing focused schema test;
3. update the schema and the matching DSL/text surface when applicable;
4. run the relevant live parser and read-back checks for stable and unstable;
5. remove or narrow any corpus baseline that no longer matches;
6. update this document only with the remaining current differences.
