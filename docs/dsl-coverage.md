# DSL coverage

`lib/dsl/` is a convenience layer over `lib/schema/`. It builds the same JSON
shapes while supplying context, converting camel-case names, and validating
assembled bodies.

This document describes reachability and validation. Parser fidelity belongs in
[`spec-coverage.md`](spec-coverage.md); text rendering belongs in
[`text-coverage.md`](text-coverage.md).

## Construction path

```text
table tree
    │
    ▼
table preparation (schema validation and scope checks)
    ├── command expansion → JSON or imperative text
    └── block emission    → table contents with rules inside chains
```

The table node is lazy. Validation runs when output is forced, either by
rendering `dsl.ruleset [...]` or calling `toTextBlock*`. Both paths share
[`lib/table.nix`](../lib/table.nix), which keeps rules with their chains until
command expansion needs a flat list. Its prepared table shape stays private;
block emission passes each chain's rules directly to the text spelling helper.
Command builders validate their own bodies before wrapping them in commands,
and statement and expression builders validate the values they build.

## Covered surfaces

### Expressions and fields

The DSL provides:

- protocol/metadata leaves under `fields`;
- generic payload escape hatches;
- structural expressions under `expr`;
- comparison and membership helpers at the top level.

Pre-built leaves cover common payload, metadata, routing, connection-tracking,
socket, OS fingerprint, and tunnel metadata fields, nft's transport-header
ports (`th.sport`, `th.dport`), and IGMP's fields (`igmp.type`, `mrt`,
`checksum`, and `group`). `expr.payload`, `expr.payloadRaw`,
`expr.payloadTunnel`, and raw expression attrsets cover less common parser
fields.

Each leaf names a field nft knows and loads as written in some rule: the
`integration-parse-check` check sends every leaf, unchanged, through `nft -c`.
A key that nft loads only with a refinement, such as a FIB result or an IPsec
key, has no leaf; [`api.md`](api.md#fields-and-expressions) lists these keys and
the `expr` constructors that build them.

Each key has one name in the DSL: its leaf, or the constructor that takes its
refinement. `expr.ct`, `expr.rt`, and `expr.osf` build a key with its `dir`,
`family`, or `ttl`, and throw without one, pointing to the leaf, such as
`fields.ct.mark`. `fields.meta` has no leaf for `ibriport`, `obriport`, or
`secpath`, nft's aliases for `ibrname`, `obrname`, and `ipsec`;
`types.metaKey` still accepts them as raw input.

Where nft's field name differs from a plain word, the leaf follows nft:

| Leaf                            | JSON field                | Text                              |
| ------------------------------- | ------------------------- | --------------------------------- |
| `udplite.csumcov`               | `csumcov`                 | `udplite csumcov`                 |
| `arp.saddrEther`, `arp.saddrIp` | `saddr ether`, `saddr ip` | `arp saddr ether`, `arp saddr ip` |
| `arp.daddrEther`, `arp.daddrIp` | `daddr ether`, `daddr ip` | `arp daddr ether`, `arp daddr ip` |
| `icmpv6.paramProblem`           | `parameter-problem`       | `icmpv6 param-problem`            |

There is no `icmpv6.packetTooBig` leaf, because nft has no such field;
`icmpv6.mtu` reads the MTU of a Packet Too Big message. There is no
`ct.count` leaf either: `ct count` is a statement (`dsl.ctCount`), not a ct
key.

`expr.set` is the anonymous-set constructor; `expr.setRef` is the named-set
reference, the `"@name"` string `inSet` requires. `expr.map` and `vmap` take
an anonymous map or a named map's name, and wrap a list of key-value pairs in
an anonymous map. Every builder that names an
object takes the name with or without its `@`, and emits `"@name"` for a set,
map, or flowtable and the bare name for a stateful object
([API reference](api.md#references-to-named-objects)). A name that declares
or selects an object, such as `add.element`'s, a Selector's, or `meter`'s,
drops a leading `@`.

### Statements

Every schema statement tag has either a named constructor or a raw body path.
Common constructors are pre-built; a variant namespace adds only the forms an
attrset can't express, such as `counter.ref` and `counter.auto`.

Three names differ deliberately:

- `setStmt` emits the `set` statement;
- `mapStmt` emits the `map` statement;
- `resetStmt` emits the `reset` statement.

The shorter names are already used: `set` and `map` by expression
constructors, and `reset` by the `reset.<kind>` command builders.

`xt` has no constructor
([schema coverage](spec-coverage.md#3-read-backinput-asymmetries)).

### Declarative objects and rules

`dsl.table family name body` supports table options, named objects, chains, and
ordered rules. The object-kind registry in
[`lib/dsl/structure/object-kinds.nix`](../lib/dsl/structure/object-kinds.nix)
provides each plural DSL key, singular JSON tag, schema body, and key-renaming
function from one source.

Expansion is deterministic:

1. table;
2. all chains, sorted by name;
3. stateful objects, which set and map elements can name: counters, quotas,
   limits, ct helpers, ct timeouts, ct expectations, secmarks, synproxies, and
   ct counts; then the other kinds alphabetically; names remain sorted within
   each kind;
4. rules grouped by sorted chain name and kept in source order within each
   chain.

This covers dependencies expressed by the table tree. Dependencies hidden in
raw nested bodies remain the caller's responsibility.

A set or map takes its elements in its own body. The tree has no top-level
`elements` key; `add.element` in a `dsl.ruleset` adds elements to a set
defined elsewhere.

Nesting owns scope. A `dsl.table` body's explicit `family` and `name` must
match its positional arguments. A named object's or chain's explicit `family`,
`table`, and `name` must match the enclosing table and collection key. A rule's explicit
`family`, `table`, and `chain` must match its parent table and chain. Matching
fields are accepted for composition; conflicting fields fail with their tree
path in both command and block output. Use standalone commands for scope that
differs from the tree, including rules intended for another chain.

Each emitted body is validated with a path such as
`chains.input.rules.0` or `sets.trusted`. A field's module-system error names
the tree first, as in `"dsl.table inet.fw".chains.input.prio`. Unknown
table-body keys fail with the table name, the offending key, and the keys a
Table tree takes, and a singular kind name points to its plural, such as
`sets` for `set`. This prevents misspellings such as `chians` from being
silently dropped. A rule entry's `index` throws, since the list order is the
rule order. `dsl.table` marks the tree with `_type = "nix-nftypes.tableTree"`,
which Cleaning strips, so a body's own `_type` throws.

### Commands

The DSL exposes all modelled command verbs:

- `add.<kind>` for the 16 add-object kinds, including `add.rule`;
- `insert.rule` and `replace.rule` for rule commands;
- `create.<kind>`, excluding `rule`;
- `delete.<kind>` and `destroy.<kind>` for the add-object kinds except
  `ctCount`, `ctTimeout`, and `ctExpectation`;
- `list.<kind>` for table, chain, set, map, counter, quota, limit, ctHelper,
  secmark, meter, and ruleset;
- `reset.<kind>` for counter, quota, set, map, and element;
- `flush.<kind>` for ruleset, table, chain, set, map, and meter;
- `rename.chain`.

`delete`, `destroy`, `list`, `flush`, and `reset` take a Selector, which
selects an object by family, table, and name alone, a rule by its chain and
handle, and elements by their set and values, and rejects every other field.
`delete` selects a table, chain, set, map, flowtable, or stateful object but a
ct helper by name or by handle
([API reference](api.md#commands)).

Each namespace offers only the kinds that nft runs as written. `create.rule`,
`flush.flowtable`, `reset.rule`, and `list` of a rule, element, flowtable,
synproxy, `metainfo`, or ct count are absent because the live JSON parser
rejects those commands. Delete, destroy, and list of a ct timeout or ct
expectation, and delete and destroy of a ct count, are absent because nft
mishandles them; see
[`spec-coverage.md`](spec-coverage.md#commands-nft-mishandles).

No command builder and no table-tree kind builds a tunnel object: nft's JSON
parser loads a tunnel's ports wrongly, and nft aborts on delete, destroy, and
list of one. The `tunnel.ref` statement, which references a tunnel object,
remains.

## Key renaming

Every DSL field and object-kind name is camel case. The DSL translates it where
nftables uses spaces, hyphens, or underscores, runs words together, names a
list of elements or statements in the singular, or names a field for something
other than what it holds. Examples:

| DSL              | JSON                                                            |
| ---------------- | --------------------------------------------------------------- |
| `ctHelper`       | `ct helper`                                                     |
| `queueThreshold` | `queue-threshold`                                               |
| `gcInterval`     | `gc-interval`                                                   |
| `rateUnit`       | `rate_unit`                                                     |
| `typeFlags`      | `type_flags`                                                    |
| `newName`        | `newname`                                                       |
| `elements`       | `elem`, in a set, map, or element body                          |
| `element`        | `elem`, in `setStmt`                                            |
| `key`            | `elem`, in `mapStmt`                                            |
| `dataType`       | `map`, in a map body                                            |
| `statements`     | `expr` in a rule; `stmt` in a set, map, `setStmt`, or `mapStmt` |
| `statement`      | `stmt`, in `meter`                                              |
| `code`           | `expr`, in `reject`                                             |

Each field has one spelling: a JSON spelling throws in a statement, a command
builder, or a table tree, and points to the DSL name.

The mapping and the JSON-spelling check are centralized in
[`lib/dsl/internal/rename.nix`](../lib/dsl/internal/rename.nix).

## Validation boundaries

Not every value under `dsl` is validated at constructor call time. Nix is lazy,
and Field leaves are fixed attrsets, which the enum-extraction and parse
checks cover. Validation occurs when a statement builder, a match operator, an
expression builder, a command builder, or table preparation applies the
matching schema body and the result is forced. A statement builder or match
operator validates its statement, and the expressions in it, against the body
`types.statement` takes for its tag, and an `expr` builder its expression
against the body `types.expression` takes, so a nested expression is checked
by each builder that holds it. `expr.setRef` checks its name itself. Field
errors are the module system's, whose option path starts with the builder, as
in `dsl.log.level`, `dsl.eq.left`, or `dsl.expr.ct.key`, and may name a field
by its JSON spelling.

`dsl.ruleset` also accepts raw command attrsets so callers can use parser forms
not covered by the convenience API. Those raw children are passed through and
are not validated automatically; only their order is checked, so a reset that
nft would ignore throws. A statement builder in a raw command still validates
its statement. The renderers likewise do not turn arbitrary raw input into a
typed value.

Validate raw user configuration explicitly with
`nftlib.validate nftlib.types.ruleset`. See
[`api.md`](api.md#validation-model).

## Intentional limits

- Plural `list`/`reset` command-selector forms are not modelled by either schema
  or DSL.
- Text rendering may impose stricter token and quoting rules than JSON.
- A raw attrset remains the escape hatch for parser-valid shapes outside the
  model.

These are model limits, not hidden DSL parity claims.

## Verification

The relevant checks are:

- the `nix-unit` schema and DSL parity suites for byte-identical raw/DSL
  JSON;
- the `nix-unit` DSL validation suite for rejected fields, unknown table
  keys, and error messages that name the offending path;
- `integration-dsl` for every Integration case through `nft -c -j -f`, and
  raw negative cases that nft and the schema must both reject;
- `integration-parse-check` for every expected DSL parity JSON value and every
  Field leaf through `nft -c`;
- focused safety suites for comments, interface names, references, tokens,
  units, priorities, and restricted types.

Each check uses the `lib` and `nft` packages of the nixpkgs it evaluates: the
locked input or one of the project policy's stable and unstable pins.

When adding a schema tag or object kind, add the constructor/registry entry,
positive parity coverage, one invalid-body test, and an Integration case that
uses it in the same change. The `nix-unit` reach check fails for a statement
tag, expression tag, or command/object pair that no Integration case uses.
