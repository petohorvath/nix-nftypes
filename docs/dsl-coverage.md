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
Command builders validate their own bodies before wrapping them in commands.

## Covered surfaces

### Expressions and fields

The DSL provides:

- protocol/metadata leaves under `fields`;
- generic payload escape hatches;
- structural expressions under `expr`;
- comparison and membership helpers at the top level.

Pre-built leaves cover common payload, metadata, routing, connection-tracking,
socket, OS fingerprint, and tunnel metadata fields. `expr.payload`,
`expr.payloadRaw`, `expr.payloadTunnel`, and raw expression attrsets cover
less common parser fields.

Each leaf names a field nft knows and loads as written: the
`integration-parse-check` check sends every leaf, unchanged, through `nft -c`.
A key that nft loads only with a refinement has no leaf. A FIB result needs
`saddr` or `daddr` among its flags, and every IPsec key and the conntrack keys
`saddr`, `daddr`, `proto-src`, and `proto-dst` need a direction, so `expr.fib`,
`expr.ipsec`, and `expr.ct` build them.

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
reference. `expr.map` and `expr.mapRef` make the same distinction for maps.
Both references return the `"@name"` string. Every builder that names an
object takes the name with or without its `@`, and emits `"@name"` for a set,
map, or flowtable and the bare name for a stateful object
([API reference](api.md#references-to-named-objects)).

### Statements

Every schema statement tag has either a named constructor or a raw body path.
Common constructors are pre-built; less common variants use callable attrsets
or `.raw`/body forms.

Two names differ deliberately:

- `setStmt` emits the `set` statement;
- `mapStmt` emits the `map` statement.

The shorter `set` and `map` names are already used by expression constructors.

`xt` exists for read-back compatibility even though nftables rejects it as new
JSON input.

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
   ct counts; then the other kinds alphabetically; then standalone elements,
   after their set/map definitions; names remain sorted within each kind;
4. rules grouped by sorted chain name and kept in source order within each
   chain.

This covers dependencies expressed by the table tree. Dependencies hidden in
raw nested bodies remain the caller's responsibility.

Nesting owns scope. A `dsl.table` body's explicit `family` and `name` must
match its positional arguments. A named object's or chain's explicit `family`,
`table`, and `name` must match the enclosing table and collection key. A rule's explicit
`family`, `table`, and `chain` must match its parent table and chain. Matching
fields are accepted for composition; conflicting fields fail with their tree
path in both command and block output. Use standalone commands for scope that
differs from the tree, including rules intended for another chain.

Each emitted body is validated with a path such as
`chains.input.rules.0` or `sets.trusted`. Unknown table-body keys fail with the
table name and offending key. This prevents misspellings such as `chians` from
being silently dropped. The documented `_type` composability marker is accepted
and removed during expansion.

### Commands

The DSL exposes all modelled command verbs:

- `add.<kind>` for the 16 add-object kinds, including `add.rule`;
- `insert.rule` and `replace.rule` for rule commands;
- `create.<kind>`, excluding `rule`;
- `delete.<kind>` and `destroy.<kind>` for the add-object kinds except
  `ctCount`, `ctTimeout`, and `ctExpectation`;
- `list.<kind>` for table, chain, set, map, counter, quota, limit, ctHelper,
  secmark, and meter;
- `reset.<kind>` for counter, quota, set, map, and element;
- `flush.<kind>` for ruleset, table, chain, set, map, and meter;
- `rename.chain`.

`delete`, `destroy`, `list`, `flush`, and `reset` select an object by family,
table, and name alone, and a rule by its chain and handle
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
nftables uses spaces, hyphens, or underscores. Examples:

| DSL              | JSON              |
| ---------------- | ----------------- |
| `ctHelper`       | `ct helper`       |
| `queueThreshold` | `queue-threshold` |
| `gcInterval`     | `gc-interval`     |
| `rateUnit`       | `rate_unit`       |
| `typeFlags`      | `type_flags`      |

The mapping is centralized in
[`lib/dsl/internal/rename.nix`](../lib/dsl/internal/rename.nix).

## Validation boundaries

Not every value under `dsl` is validated at constructor call time. Nix is lazy,
and leaf constructors generally build attrsets. Validation occurs when a
command builder or table preparation applies the matching schema body and the
result is forced.

`dsl.ruleset` also accepts raw command attrsets so callers can use parser forms
not covered by the convenience API. Those raw children are passed through and
are not validated automatically; only their order is checked, so a reset that
nft would ignore throws. The renderers likewise do not turn arbitrary raw input
into a typed value.

Validate raw user configuration explicitly with
`nftlib.validate nftlib.types.ruleset`. See
[`api.md`](api.md#validation-model).

## Intentional limits

- Plural `list`/`reset` command-selector forms are not modelled by either schema
  or DSL.
- Some command verbs accept slimmer parser selector bodies than the shared
  schema bodies expose.
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
