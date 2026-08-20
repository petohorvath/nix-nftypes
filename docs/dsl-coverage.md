# DSL coverage

`lib/dsl/` is a convenience layer over `lib/schema/`. It builds the same JSON
shapes while supplying context, converting camel-case names, and validating
assembled bodies.

This document describes reachability and validation. Parser fidelity belongs in
[`spec-coverage.md`](spec-coverage.md); text rendering belongs in
[`text-coverage.md`](text-coverage.md).

## Construction path

```text
field / expression / statement constructors
                     │
                     ▼
       table tree and command builders
                     │
          schema-body validation
                     │
                     ▼
       flat libnftables command attrsets
                     │
          JSON or text renderer
```

The table node is lazy. Validation runs when expansion is forced, normally by
rendering `dsl.ruleset [...]`.

## Covered surfaces

### Expressions and fields

The DSL provides:

- protocol/metadata leaves under `fields`;
- generic payload escape hatches;
- structural expressions under `expr`;
- comparison and membership helpers at the top level.

Pre-built leaves cover common payload, metadata, routing, connection-tracking,
FIB, socket, OS fingerprint, and XFRM fields. `payload`, `payloadRaw`,
`payloadTunnel`, and raw expression attrsets cover less common parser fields.

`expr.set` is the anonymous-set constructor; `expr.setRef` is the named-set
reference. `expr.map` and `expr.mapRef` make the same distinction for maps.

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
3. object kinds alphabetically, except standalone elements follow their set/map
   definitions; names remain sorted within each kind;
4. rules grouped by sorted chain name and kept in source order within each
   chain.

This covers dependencies expressed by the table tree. Dependencies hidden in
raw nested bodies remain the caller's responsibility.

Each emitted body is validated with a path such as
`chains.input.rules.0` or `sets.trusted`. Unknown table-body keys fail with the
table name and offending key. This prevents misspellings such as `chians` from
being silently dropped. The documented `_type` composability marker is accepted
and removed during expansion.

### Commands

The DSL exposes all modelled command verbs:

- `rule`, `replace`, and `insert` for rule commands;
- `create.<kind>`, excluding `rule`;
- `delete.<kind>` and `destroy.<kind>` for the 16 add-object kinds;
- `list.<kind>` plus `list.metainfo` and `list.meter`;
- `reset.<kind>` for counter, quota, rule, set, map, and element;
- `flush` plus explicit ruleset/table/chain/set/map/meter helpers;
- `rename.chain`.

`create.rule` and `flushFlowtable` are absent because the live JSON parser
rejects those commands.

## Key renaming

The DSL uses Nix-friendly camel case and translates only where nftables uses
hyphenated names. Examples:

| DSL | JSON |
| --- | --- | --- |
| `ctHelper` | `ct helper` |
| `queueThreshold` | `queue-threshold` |
| `gcInterval` | `gc-interval` |
| `srcIpv4` | `src-ipv4` |

The mapping is centralized in
[`lib/dsl/internal/rename.nix`](../lib/dsl/internal/rename.nix).

## Validation boundaries

Not every value under `dsl` is validated at constructor call time. Nix is lazy,
and leaf constructors generally build attrsets. Validation occurs when a
command builder or table expansion applies the matching schema body and the
result is forced.

`dsl.ruleset` also accepts raw command attrsets so callers can use parser forms
not covered by the convenience API. Those raw children are passed through and
are not validated automatically. The renderers likewise do not turn arbitrary
raw input into a typed value.

Use `nftlib.types.ruleset` explicitly for raw user configuration. See
[`api.md`](api.md#validation-model).

## Intentional limits

- Plural `list`/`reset` command-selector forms are not modelled by either schema
  or DSL.
- Some command verbs accept slimmer parser selector bodies than the shared
  schema bodies expose.
- Stateful-object map statements and several null-body statement spellings are
  known schema gaps, so they have no typed DSL path.
- Text rendering may impose stricter token and quoting rules than JSON.
- A raw attrset remains the escape hatch for parser-valid shapes outside the
  model.

These are model limits, not hidden DSL parity claims.

## Verification

The relevant checks are:

- `schema-tests` and DSL parity cases for byte-identical raw/DSL JSON;
- `dsl-validation-tests` for rejected fields and unknown table keys;
- `dsl-validation-message-tests` for useful error paths;
- `integration-tests` for selected DSL output through `nft -c -j -f` and a
  raw `create rule` parser-rejection case;
- focused safety suites for comments, interface names, references, tokens,
  units, priorities, and restricted types.

Stable and unstable variants use their respective nixpkgs `lib` and `nft`
packages.

When adding a schema tag or object kind, add the constructor/registry entry,
positive parity coverage, one invalid-body test, and the applicable live-parser
case in the same change.
