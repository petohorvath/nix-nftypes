# API reference

The flake exports a system-independent `lib`. Import it as:

```nix
nftlib = inputs.nix-nftypes.lib;
```

## Validation model

There are three distinct operations:

1. **Validation** through `nftlib.validate` and the `nftlib.types` schema.
2. **DSL construction**, which validates assembled table objects, chains, rules,
   and command-builder bodies when evaluation forces them.
3. **Rendering**, which cleans and serializes a value but does not perform a
   complete schema validation pass on arbitrary raw attrsets.

Validate hand-written input explicitly with `validate type value`:

```nix
let
  raw = {
    nftables = [
      { flush = { ruleset = null; }; }
      { add = { table = { family = "inet"; name = "filter"; }; }; }
    ];
  };
in
nftlib.toJson (nftlib.validate nftlib.types.ruleset raw)
```

`validate` takes any schema type and returns the value with option defaults
filled in, which rendering cleans away. It forces the whole value, so every
check runs before it returns, however deep. A mismatch throws the module
system's error, whose option path starts with `validate`, such as
`validate.nftables."[definition 1-entry 2]".add.chain.policy`.

`dsl.ruleset` accepts table nodes, nested lists, and raw command attrsets. Table
nodes are expanded and validated; raw command attrsets are deliberately passed
through as an escape hatch. Only the order of the commands is checked: a reset
that nft would ignore throws (see [Commands](#commands)).

Table trees derive scope from nesting. Explicit `family` and `name` fields in a
`dsl.table` body must match its positional arguments; `family`, `table`, and
`name` fields on named objects and chains must match the enclosing table and
collection key; `family`, `table`, and `chain` on rules must match their parent
table and chain. Matching fields are accepted. Conflicts raise an error naming the field,
for example `chains.input.rules.0.chain`, in both command and block rendering.
Explicit command builders and raw commands remain available for independently
chosen scope.

Every library error starts `nix-nftypes: <API>: `, naming what the caller
called: a builder such as `dsl.create.ctCount`, a table tree as
`dsl.table inet.t` followed by the field's path, `text` for the text renderers,
`types.statementOf`, or a helper such as `resolvePriority`. A text Refusal ends
with `Field: <label>.` ([ADR 0004](adr/0004-refuse-unsafe-text.md)).

## Schema types

`nftlib.types` combines primitive and composable types.

### Main types

| Type | Shape |
| --- | --- |
| `ruleset` | `{ nftables = [ ... ]; }` envelope; a reset of a counter, quota, set, map, or rule only as its last entry |
| `command` | one command wrapper such as `add`, `delete`, or `flush` |
| `expression` | scalar, list, or tagged expression |
| `taggedExpression` | tagged-expression forms only |
| `statement` | one tagged rule statement |
| `addObject` | the 16 add-object tags; a rule takes no `handle` |
| `createObject` | add-object tags except `rule` |
| `deleteObject` | add-object tags except `ct count`, `ct timeout`, and `ct expectation`; used by `delete` and `destroy` |
| `listObject` | table, chain, set, map, counter, quota, limit, ct helper, secmark, or meter |
| `readBackObject` | a bare listed object, as `nft -j list` emits: add-object tags plus `metainfo`, `meter`, and the Read-back-only `tunnel`; a rule keeps its `handle` |
| `flushObject` | table, chain, set, map, meter, or ruleset |
| `resetObject` | counter, quota, rule, set, map, or element |
| `replaceObject` | a rule with the `handle` of the rule it replaces |
| `renameObject` | a chain with its `newname` |

Per-variant submodules are grouped under:

- `types.expressions`;
- `types.statements`;
- `types.objects`.

Each submodule takes only an attrset of its fields. Unlike `lib.types.submodule`,
it rejects a module function, a path, and a `_module` key, so a string in a
union with a body, such as the synproxy reference `"/sp1"`, is a name rather
than a module file to import.

Primitive types include `family`, `hook`, `chainType`, `policy`, `portNumber`,
`prefixLength`, `ifname`, `nftQuotedString`, `logPrefix`, `namedReference`
(`"@name"`), `nullLiteral` (the JSON `null` of a body such as
`{ counter = null; }`), and the enum-backed types listed in `nftlib.enums`.

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

Use `payload protocol field`, `payloadRaw`, and `payloadTunnel` when no
pre-built leaf exists. Structural and generated expressions live under
`dsl.expr`, including `concat`, `prefix`, `range`, `set`, `setRef`, `map`,
`mapRef`, `numgen`, `jhash`, and `symhash`.

Top-level match helpers include:

- `eq`, `ne`, `lt`, `gt`, `le`, `ge`;
- `inSet`, `notInSet`, `within`;
- `match.in_` and `match.raw` for less common forms.

`inSet`, `notInSet`, and `within` take a list, a set expression, or a named-set
reference such as `"@trusted"`. A string without `@` throws and points to
`expr.setRef`: nft would match it as one value, such as a hostname.

`expr.set [ ... ]` creates an anonymous set. `expr.setRef "name"` and
`expr.mapRef "name"` return the reference string `"@name"`, the shape nft
lists, for the right side of a match or the data of a map lookup or `vmap`.
The map lookup is `expr.map key data`:

```nix
expr.map fields.tcp.dport (expr.mapRef "ports")
```

#### References to named objects

Every builder that references a named object takes the name with or without
its leading `@`, and emits the spelling nft's JSON parser looks up there:

| Position | Builders | Emitted |
| --- | --- | --- |
| a set, map, or flowtable | `expr.setRef`, `expr.mapRef`, `expr.map`, `vmap`, `setStmt`, `mapStmt`, `flow` | `"@name"`; nft reads a bare name as a hostname or a symbol |
| a stateful object | the `.ref` of `counter`, `quota`, `limit`, `synproxy`, `ctCount`, `ctHelper`, `ctTimeout`, `ctExpectation`, `secmark`, and `tunnel` | the bare name; nft finds no object named `"@name"` |

A stateful object's `.ref` also takes a map expression, which selects the
object by key. `inSet`, `notInSet`, and `within` are the exception: their
right side need not be a set, so they take `"@name"` and throw on a string
without `@`.

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
counter { packets = 0; bytes = 0; }
counter.ref "named_counter"
counter.auto
quota.ref (expr.map fields.tcp.dport "quota_by_port")
ctHelper.ref "ftp"

reject.icmpx "admin-prohibited"
log { prefix = "DROP: "; level = "info"; }
limit { rate = 10; per = "minute"; burst = 5; }
```

`.ref name` references a named object. `ctHelper`, `ctTimeout`,
`ctExpectation`, `secmark`, and `tunnel` have no other form, so calling one
directly throws and points to its `.ref`. `.auto` is the null-body form, such
as `{ counter = null; }`, that `nft -j list --stateless` prints; `counter` and
`synproxy` have it. A statement whose fields are all optional takes `{ }` for
its empty form, for example `log { }` or `masquerade { }`.

`counter` has no `{ }` form. nft parses an inline counter only with both
`packets` and `bytes`, so `counter { }` and a counter with one of them throw.
`counter.auto` is the unseeded counter.

`reject` takes `{ type?; expr?; }`, and its variants `reject.icmp code`,
`reject.icmpv6 code`, and `reject.icmpx code` answer with an ICMP, ICMPv6, or
family-independent ICMPX code; `reject.tcpReset` answers with a TCP reset.

The conntrack statements are `ctHelper.ref`, `ctTimeout.ref`, and
`ctExpectation.ref`, which assign a named ct helper, timeout, or expectation to
the connection, and `ctCount { val; inv?; }` or `ctCount.ref name`, which
matches on the number of connections. `secmark.ref` applies a named secmark and
`tunnel.ref` attaches a named tunnel.

`reset expr` resets the stateful data an expression selects, such as a TCP
option: `reset (expr.tcpOption { name = "sack"; })`. The same `reset` carries
the `reset.<kind>` command builders.

Other top-level constructors include `snat`, `dnat`, `masquerade`, `redirect`,
`queue`, `synproxy`, `flow`, `meter`, `vmap`, `mangle`, `tproxy`, `fwd`, `dup`,
`last`, and `lastUsed`.

The statement tags named `set` and `map` would collide with expression
constructors, so their DSL names are `setStmt` and `mapStmt`. Like `flow`, they
take the set, map, or flowtable name with or without its leading `@`:

```nix
setStmt { op = "add"; elem = fields.ip.saddr; set = "blocked"; }
flow { flowtable = "ft"; }
```

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
  `ctHelpers`, `ctTimeouts`, `ctExpectations`, `ctCounts`, `secmarks`, and
  `synproxies`.

Unknown keys fail evaluation. The internal `_type` marker remains accepted for
libraries that layer their own boundary tags on nftypes values; it is not
emitted. Expansion order is table, chains, named objects, then rules. Among
named objects, stateful objects come first, so a set or map element can name
one: counters, quotas, limits, ct helpers, ct timeouts, ct expectations,
secmarks, synproxies, and ct counts. The other kinds follow alphabetically, and
standalone element commands come last, after their set/map definitions. Object
and chain names are emitted in sorted order; rule order remains the source-list
order. This covers dependencies made explicit by the table tree; dependencies
hidden in raw nested bodies remain the caller's responsibility.

A rule entry is either a non-empty statement list or an attrset with a
non-empty `expr` plus optional `index` and `comment`. Any other entry throws,
naming its path, such as `chains.input.rules.0`: write a single statement as a
list, `[ dsl.drop ]`, not as the bare `dsl.drop`. A rule entry takes no
`handle`, as `add.rule` takes none.

### Naming and argument conventions

Every DSL field name is camelCase. The DSL renames it where JSON uses hyphens
or underscores, for example `queueThreshold` to `queue-threshold`, `gcInterval`
to `gc-interval`, `rateUnit` to `rate_unit`, and
`typeFlags` to `type_flags`. The same renames apply to statements, table-tree
objects, and command builders. Named sets and maps also take `elements` for the
JSON `elem` key. A body that gives both spellings of a field, such as
`elements` and `elem`, throws instead of keeping one of them.

A body is an attrset of fields, never a module. A string in a body position,
such as `create.counter "c1"`, throws naming its path, and a string in a name or
reference position, such as `synproxy.ref "/sp1"`, is a name. Module keys such
as `imports` are unknown fields, and `_module` throws.

A builder takes positional arguments only when every argument is required and
there are at most two, as in `eq left right`, `vmap key data`, `expr.map key
data`, `payload protocol field`, `prefix addr len`, and `counter.ref name`.
Every other builder takes one attrset. `dsl.table family name body` is the
exception; it mirrors nftables' `table inet filter { … }` syntax. See
[ADR 0009](adr/0009-dsl-naming-and-argument-conventions.md).

### Commands

| API | Notes |
| --- | --- |
| `add.<kind>` | 16 add-object kinds; `add.rule` adds a standalone rule |
| `create.<kind>` | 15 object kinds; `rule` is excluded |
| `delete.<kind>`, `destroy.<kind>` | 13 add-object kinds; not `ctCount`, `ctTimeout`, or `ctExpectation` |
| `flush.<kind>` | table, chain, set, map, meter, or ruleset; nftables has no `flush flowtable` command |
| `list.<kind>` | table, chain, set, map, counter, quota, limit, ctHelper, secmark, or meter |
| `reset.<kind>` | counter, quota, set, map, or element |
| `replace body`, `insert body` | rule-only commands |
| `rename.chain body` | chain-only rename |

Each `<verb>.<kind>` builder takes one object body. `flush.ruleset { }` flushes
every family, and `flush.ruleset { family = "ip"; }` flushes one.

In one batch, nft runs a `reset` of a counter, quota, set, or map only as the
last command: followed by any other command, it resets nothing, and nft still
exits 0. `types.ruleset` rejects a ruleset with such a reset anywhere else,
and `dsl.ruleset` throws for one, whether a builder or a raw attrset made it.
Give each one a ruleset of its own, or put it last. `reset.element` runs
anywhere.

Each namespace offers only the kinds that nft runs as written, measured on
nftables 1.1.6 and 1.1.7:

- nft rejects `list` of a rule, element, flowtable, synproxy, `metainfo`, or ct
  count, and the JSON `reset rule`, so those builders are absent, and
  `types.command` rejects those `list` commands.
- nft mishandles delete and destroy of a ct expectation (it deletes the whole
  table), list of one (it lists the table), and delete, destroy, and list of a
  ct timeout. nftables 1.1.7 aborts on delete and destroy of a ct count. Those
  builders are absent, and `types.command` rejects the commands; see
  [`spec-coverage.md`](spec-coverage.md#commands-nft-mishandles).
- No namespace and no table-tree kind builds a tunnel object. nft's JSON
  parser loads a tunnel's ports wrongly, and nft aborts on delete, destroy,
  and list of one. `types.command` rejects every tunnel command, and
  `types.ruleset` accepts a tunnel only as Read-back.

Command builders validate against the verb's schema body, so a builder throws
when the body lacks a field nft requires for the verb, naming the field:

- A chain sets `type`, `hook`, and `prio` together (a base chain) or none of
  them, in every builder and in a table tree's `chains`. nft loads a chain
  with only some of them as a regular chain whose rules never see packets.

- `add.flowtable` and `create.flowtable` require `hook` and `prio`.
- `replace` requires the `handle` of the rule it replaces.
- `add.rule` takes no `handle`, and throws naming the field
  (`dsl.add.rule.handle`). nftables 1.1.6's JSON parser ignores one and
  appends the rule, while 1.1.7 and text place the rule after the rule with
  that handle. Place a rule with `index`, or with `insert`, whose `handle`
  puts it before that rule; see
  [`spec-coverage.md`](spec-coverage.md#rule-handles-on-add-rule).
- `add.rule`, `insert`, and `replace` require statements, a non-empty `expr`
  list, as a table tree's rule entries do. Without them, the builder throws,
  naming the command, such as `add.rule`.
- `rename.chain` requires `newname`.

`delete`, `destroy`, `list`, `flush`, and `reset` select an object by
`family`, `table`, and `name`, and demand no field that nft ignores for the
verb: a set's or map's datatypes, a limit's rate, a flowtable's hook, and a
synproxy's `mss` and `wscale` are optional there. `types.objects` holds these
selection bodies, such as `selectSetBody`. Every `delete.<kind>` but
`delete.rule` requires `name`, though nft also deletes most kinds by `handle`
alone ([`spec-coverage.md`](spec-coverage.md)); `destroy.<kind>` requires it
in nft too.

A rule is selected by its `chain` and `handle`, which `delete.rule` and
`destroy.rule` require as a positive integer: nft takes handle 0 as none, and
the kernel then deletes every rule in the chain.

## Renderers

### `toJson value`

Returns compact JSON via `builtins.toJSON` after `cleanValue` normalization.
Use the result with `nft -j -f`.

`toJson`, `toNix`, `toText`, and `toTextPretty` take a ruleset, not a table
tree. A `dsl.table` value passed alone or among the `nftables` commands throws
and asks for `dsl.ruleset [ … ]`, which expands it into commands.

### `toNix value`

Returns a human-readable Nix representation after the same normalization. It is
a diagnostic formatter, not JSON and not input for `nft`.

### `toText value` and `toTextPretty value`

Render imperative nftables commands. The compact form minimizes whitespace;
the pretty form uses readable multi-line blocks. Both are pure Nix.

### `toTextBlock tableNode` and `toTextBlockPretty tableNode`

Render only the contents of one `dsl.table` node. These functions omit the
outer table declaration, keep the table's `flags` and `comment` as the first
declarations, and place rules inside their chain blocks. A table `handle` has
no block-form spelling and is omitted. Passing a full ruleset or a raw command
is an error.

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
`{ ruleset = null; }`, also when the value carries a `_type` marker.

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
  unknown family or symbol. It resolves a bare symbol only, so add an offset
  with Nix arithmetic: `resolvePriority "ip" "filter" + 10`.
- `priorityNameOf family value` maps a known int to its canonical symbol and
  otherwise returns the original value. Integer lookup throws on an unknown
  family; symbols pass through without consulting `family`.
- `chainTypeFor family hook priority` classifies the project's conventional
  chain type policy. NAT priorities map to `nat` and the `mangle` priority to
  `route`, unless `validChainPlacement` rejects that type at the hook, in the
  family; every other placement maps to `filter`. So
  `chainTypeFor "bridge" "postrouting" 300` (bridge `srcnat`) and
  `chainTypeFor "ip" "forward" "dstnat"` return `filter`. An unknown symbol
  returns `null`.
- `validChainPlacement family chainType hook` checks the static family,
  chain-type, and hook tables.

These helpers do not inspect kernel versions, loaded modules, devices, or
runtime state. An `inet`/`netdev` ingress chain can still require `dev`, for
example, even when the static triple is valid.
