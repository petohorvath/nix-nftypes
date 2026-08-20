# API reference

The flake exports a system-independent `lib`. Import it as:

```nix
nftlib = inputs.nix-nft-types.lib;
```

## Validation model

There are three distinct operations:

1. **Schema validation** through `nftlib.types` and `lib.evalModules`.
2. **DSL construction**, which validates assembled table objects, chains, rules,
   and command-builder bodies when evaluation forces them.
3. **Rendering**, which cleans and serializes a value but does not perform a
   complete schema validation pass on arbitrary raw attrsets.

Validate hand-written input explicitly:

```nix
let
  lib = inputs.nixpkgs.lib;
  raw = {
    nftables = [
      { flush = { ruleset = null; }; }
      { add = { table = { family = "inet"; name = "filter"; }; }; }
    ];
  };

  checked = (lib.evalModules {
    modules = [
      {
        options.value = lib.mkOption {
          type = nftlib.types.ruleset;
        };
      }
      { value = raw; }
    ];
  }).config.value;
in
nftlib.toJson checked
```

`dsl.ruleset` accepts table nodes, nested lists, and raw command attrsets. Table
nodes are expanded and validated; raw command attrsets are deliberately passed
through as an escape hatch.

## Schema types

`nftlib.types` combines primitive and composable types.

### Main types

| Type | Shape |
| --- | --- |
| `ruleset` | `{ nftables = [ ... ]; }` envelope |
| `command` | one command wrapper such as `add`, `delete`, or `flush` |
| `expression` | scalar, list, or tagged expression |
| `taggedExpression` | tagged-expression forms only |
| `statement` | one tagged rule statement |
| `addObject` | the 16 add-object tags |
| `createObject` | add-object tags except `rule` |
| `listObject` | add-object tags plus `metainfo` and `meter` |
| `flushObject` | table, chain, set, map, meter, or ruleset |
| `resetObject` | counter, quota, rule, set, map, or element |

Per-variant submodules are grouped under:

- `types.expressions`;
- `types.statements`;
- `types.objects`.

Primitive types include `family`, `hook`, `chainType`, `policy`, `portNumber`,
`prefixLength`, `ifname`, `nftQuotedString`, and the enum-backed types listed in
`nftlib.enums`.

### Restricted tag sets

Use `statementOf` and `expressionOf` when a downstream option should accept
only selected tags:

```nix
matchPrefix = lib.mkOption {
  type = lib.types.listOf (nftlib.types.statementOf [ "match" ]);
  default = [ ];
};

terminalVerdict = lib.mkOption {
  type = nftlib.types.statementOf [
    "accept"
    "drop"
    "jump"
    "goto"
    "return"
    "continue"
  ];
};
```

`types.matchStatement` is `statementOf [ "match" ]`.

`expressionOf` covers tagged expressions only. Compose it with scalar types if
the option also accepts scalars:

```nix
type = lib.types.oneOf [
  lib.types.str
  lib.types.int
  (nftlib.types.expressionOf [ "payload" "meta" ])
];
```

Unknown tag names fail while constructing the restricted type.

## DSL

### Fields and expressions

Common field leaves live under `dsl.fields`:

```nix
nftlib.dsl.fields.tcp.dport
nftlib.dsl.fields.ip.saddr
nftlib.dsl.fields.ct.state
nftlib.dsl.fields.meta.iifname
nftlib.dsl.fields.fib.oif
```

Use `payload`, `payloadRaw`, and `payloadTunnel` when no pre-built leaf exists.
Structural and generated expressions live under `dsl.expr`, including
`concat`, `prefix`, `range`, `set`, `setRef`, `map`, `mapRef`, `numgen`,
`jhash`, and `symhash`.

Top-level match helpers include:

- `eq`, `ne`, `lt`, `gt`, `le`, `ge`;
- `inSet`, `notInSet`, `within`;
- `match.in_` and `match.raw` for less common forms.

`expr.set [ ... ]` creates an anonymous set. `expr.setRef "name"` emits a named
set reference. The equivalent map helpers are `expr.map` and `expr.mapRef`.

### Statements

Verdicts are values:

```nix
accept
drop
continue
return
notrack
```

`jump target` and `goto target` carry a chain target.

Most statement families are callable attrsets with named variants. Examples:

```nix
counter.auto
counter { packets = 0; bytes = 0; }
counter.ref "named_counter"

reject.icmpx "admin-prohibited"
log { prefix = "DROP: "; level = "info"; }
limit { rate = 10; per = "minute"; burst = 5; }
```

Other top-level constructors include `snat`, `dnat`, `masquerade`, `redirect`,
`queue`, `synproxy`, `flow`, `meter`, `vmap`, `mangle`, `tproxy`, `fwd`, `dup`,
`tunnel`, `last`, and `lastUsed`.

The statement tags named `set` and `map` would collide with expression
constructors, so their DSL names are `setStmt` and `mapStmt`.

`xt` is exposed for read-back compatibility, but nftables rejects it as JSON
input. See [`spec-coverage.md`](spec-coverage.md).

### Declarative table tree

```nix
nftlib.dsl.table "inet" "filter" {
  flags = [ "dormant" ];
  comment = "managed by Nix";

  sets.trusted = {
    type = "ipv4_addr";
    elements = [ "192.0.2.1" ];
  };

  chains.input = {
    type = "filter";
    hook = "input";
    prio = 0;
    policy = "drop";
    rules = [
      [ (nftlib.dsl.eq nftlib.dsl.fields.ip.saddr "@trusted") nftlib.dsl.accept ]
    ];
  };
}
```

Recognized table-body keys are:

- table options: `handle`, `flags`, `comment`;
- `chains`;
- `sets`, `maps`, `elements`, `flowtables`, `counters`, `quotas`, `limits`,
  `ctHelpers`, `ctTimeouts`, `ctExpectations`, `secmarks`, `synproxies`, and
  `tunnels`.

Unknown keys fail evaluation. The internal `_type` marker remains accepted for
libraries that layer their own boundary tags on nftypes values; it is not
emitted. Object and chain names are emitted in sorted order; rule order remains
the source-list order. Object kinds are alphabetical except that standalone
element commands follow their set/map definitions. Expansion order is table,
chains, named objects, then rules. This covers dependencies made explicit by the
table tree; dependencies hidden in raw nested bodies remain the caller's
responsibility.

A rule entry may be either a statement list or an attrset with `expr` plus
optional `handle`, `index`, and `comment`.

Camel-case DSL fields are renamed where JSON uses hyphens, for example
`queueThreshold` to `queue-threshold`, `gcInterval` to `gc-interval`, and
`srcIpv4` to `src-ipv4`.

### Commands

| API | Notes |
| --- | --- |
| `flush` | bare `flush ruleset` value |
| `flushRuleset`, `flushTable`, `flushChain`, `flushSet`, `flushMap`, `flushMeter` | explicit flush builders; nftables has no `flush flowtable` command |
| `rule body` | standalone `add rule` |
| `create.<kind>` | 15 object kinds; `rule` is excluded |
| `delete.<kind>`, `destroy.<kind>` | 16 add-object kinds |
| `list.<kind>` | 16 add-object kinds plus `metainfo` and `meter` |
| `reset.<kind>` | counter, quota, rule, set, map, or element |
| `replace body`, `insert body` | rule-only commands |
| `rename.chain body` | chain-only rename |

Command builders validate against the current schema body. Some nftables verbs
accept slimmer selector bodies than the shared schema models; those differences
are listed in [`spec-coverage.md`](spec-coverage.md).

## Renderers

### `toJson value`

Returns compact JSON via `builtins.toJSON` after `cleanValue` normalization.
Use the result with `nft -j -f`.

### `toNix value`

Returns a human-readable Nix representation after the same normalization. It is
a diagnostic formatter, not JSON and not input for `nft`.

### `toText value` and `toTextPretty value`

Render imperative nftables commands. The compact form minimizes whitespace;
the pretty form uses readable multi-line blocks. Both are pure Nix.

### `toTextBlock tableNode` and `toTextBlockPretty tableNode`

Render only the contents of one `dsl.table` node. These functions omit the
outer table declaration and place rules inside their chain blocks. Passing a
full ruleset or a raw command is an error.

Table-block grammar has no form for a standalone `element` command. A table
node with a top-level `elements.<name>` entry is therefore rejected. Put initial
elements directly on the corresponding `sets.<name>` or `maps.<name>`
definition, or use `toText`/`toTextPretty` when a later imperative element
update is required.

The JSON renderer is authoritative when JSON and text grammar capabilities
differ. See [`text-coverage.md`](text-coverage.md).

## Cleaning

`cleanValue` recursively removes:

- internal module markers such as `_type`;
- unset `null` fields from ordinary multi-key attrsets.

It preserves significant tagged-null forms such as `{ accept = null; }` and
`{ ruleset = null; }`.

Cleaning is not validation.

## Reference data

`nftlib.enums.<name>` exposes the same value list used by each enum type.
Examples include `family`, `hook`, `operator`, `metaKey`, `rtKey`, `fibResult`,
`setFlag`, and `tunnelType`.

`nftlib.compatibility` exports:

- `hooksByFamily`;
- `familiesByChainType`;
- `hooksByChainType`;
- `priorityIntsDefault`, `priorityIntsBridge`, `priorityIntsByFamily`;
- `hooksWithOifname`.

Top-level helpers:

- `resolvePriority family value` converts a known symbolic priority to an int.
  Ints pass through without consulting `family`; symbolic lookup throws for an
  unknown family or symbol.
- `priorityNameOf family value` maps a known int to its canonical symbol and
  otherwise returns the original value. Integer lookup throws on an unknown
  family; symbols pass through without consulting `family`.
- `chainTypeFor family hook priority` classifies the project's conventional
  chain type policy. NAT priorities map to `nat`; `mangle` priority at a
  route-capable hook maps to `route`; other recognized placements map to
  `filter`. An unknown symbol returns `null`.
- `validChainPlacement family chainType hook` checks the static family,
  chain-type, and hook tables.

These helpers do not inspect kernel versions, loaded modules, devices, or
runtime state. An `inet`/`netdev` ingress chain can still require `dev`, for
example, even when the static triple is valid.
