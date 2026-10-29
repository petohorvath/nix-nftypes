# API reference

The flake exports a system-independent `lib`. Import it as:

```nix
nftlib = inputs.nix-nftypes.lib;
```

## Validation model

There are three distinct operations:

1. **Validation** through `nftlib.validate` and the `nftlib.types` schema.
2. **DSL construction**, which validates assembled table objects, chains, rules,
   statements, expressions, and command-builder bodies when evaluation forces
   them.
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

`validate` takes any schema type and returns the value unchanged: an option the
value leaves unset stays absent. `validate` forces the whole value, so every
check runs before it returns, however deep. A mismatch throws the module
system's error, whose option path starts with `validate`, such as
`validate.nftables."[definition 1-entry 2]".add.chain.policy`. Swapped
arguments, a first argument that is not a schema type, and a table tree as
the value throw a `nix-nftypes: validate:` error instead; expand a table tree
with `dsl.ruleset [ … ]`.

`dsl.ruleset` takes a list of Table trees, rulesets, raw command attrsets, and
nested lists of these. Table trees are expanded and validated, and a ruleset's
commands are spliced in place, so `dsl.ruleset [ base extra ]` composes two
rulesets; raw command attrsets are deliberately passed through as an escape
hatch. A non-list argument or any other child throws, naming what it got. Only
the order of the commands is checked: a reset that nft would ignore throws (see
[Commands](#commands)). A statement that a builder or match operator made is
validated by it, inside a raw command too.

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
`dsl.table inet.t` followed by the field's path, a renderer such as `toText` or
`toTextBlock`, `types.statementOf`, or a helper such as
`compatibility.priorityValue`. A text Refusal is never hard-wrapped: one line
explains it, an `Offending value: <JSON>` line follows when it has a value, and
it ends with `Field: <label>.` ([ADR 0004](adr/0004-refuse-unsafe-text.md)).

## Schema types

`nftlib.types` combines primitive and composable types.

### Main types

| Type             | Shape                                                                                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ruleset`        | `{ nftables = [ ... ]; }` envelope; a reset of a counter, quota, set, map, or rule only as its last entry                                        |
| `command`        | one command wrapper such as `add`, `delete`, or `flush`                                                                                          |
| `expression`     | scalar, list, or tagged expression                                                                                                               |
| `statement`      | one tagged rule statement                                                                                                                        |
| `addObject`      | the 16 add-object tags; no body takes a `handle`                                                                                                 |
| `createObject`   | add-object tags except `rule`                                                                                                                    |
| `deleteObject`   | add-object tags except `ct count`, `ct timeout`, and `ct expectation`; used by `delete` and `destroy`                                            |
| `listObject`     | table, chain, set, map, counter, quota, limit, ct helper, secmark, or meter                                                                      |
| `readBackObject` | a bare listed object, as `nft -j list` emits: add-object tags plus `metainfo`, `meter`, and the Read-back-only `tunnel`; each keeps its `handle` |
| `flushObject`    | table, chain, set, map, meter, or ruleset                                                                                                        |
| `resetObject`    | counter, quota, rule, set, map, or element                                                                                                       |
| `insertObject`   | a rule                                                                                                                                           |
| `replaceObject`  | a rule with the `handle` of the rule it replaces                                                                                                 |
| `renameObject`   | a chain with its `newname`                                                                                                                       |

Per-variant bodies are grouped under:

- `types.expressionBodies`;
- `types.statementBodies`;
- `types.objectBodies`.

These namespaces hold bodies only, each named `<kind>Body`, such as
`types.objectBodies.setBody` and `types.statementBodies.counterBody`. A body
several tags share is named for what they share (`natBody`), a variant or a
nested part of one tag's body puts its parent first (`payloadRawBody`,
`tunnelVxlanBody`), and the body of one command puts its verb first
(`flushRulesetBody`, `insertRuleBody`, `selectSetBody`). A statement body
includes the statement's reference forms. Type a tagged object, such as
`{ chain = { … }; }`, with its command's union, such as `types.addObject` or
`types.readBackObject`.

`types.statementBodies` holds the body of each statement tag that takes more
than `null`, the same type `types.statement` takes for that tag:
`statementBodies.logBody` accepts `null` as `{ log = null; }` does. `ct helper`,
`ct timeout`, `ct expectation`, `secmark`, and `tunnel` share `objectRefBody`,
an expression: the object's name, such as `"ftp"`, or a map expression that
selects it. `jump` and `goto` take `verdictTargetBody`, the same type as
`types.expressionBodies.verdictTargetBody`. `accept`, `drop`, `continue`,
`return`, and `notrack` take only `null`, so they have no body there; type
their body with `types.nullLiteral`.

Each submodule takes only an attrset of its fields. Unlike `lib.types.submodule`,
it rejects a module function, a path, and a `_module` key, so a string in a
union with a body, such as the synproxy reference `"/sp1"`, is a name rather
than a module file to import.

Primitive types include `family`, `hook`, `chainType`, `chainPolicy`,
`portNumber`, `prefixLength`, `ifname`, `comment`, `logPrefix`, `namedReference`
(`"@name"`), `nullLiteral` (the JSON `null` of a body such as
`{ counter = null; }`), and the enum-backed types listed in `nftlib.enums`.

Type names spell their words out, even where the field they type keeps nft's
abbreviation:

| Type                    | Types                                                    | Name in 0.1.0 |
| ----------------------- | -------------------------------------------------------- | ------------- |
| `matchOperator`         | a match statement's `op`                                 | `operator`    |
| `setOperator`           | a set or map statement's `op`                            | `setOp`       |
| `flowOperator`          | a flow statement's `op`                                  | `flowOp`      |
| `ctL3Protocol`          | a ct helper, timeout, or expectation object's `l3proto`  | none          |
| `tcpUdpProtocol`        | a ct helper, timeout, or expectation object's `protocol` | `tcpUdpProto` |
| `tunnelErspanDirection` | an ERSPAN version 2 tunnel's `dir`                       | none          |

A tunnel object's `tunnel` field takes
`types.objectBodies.tunnelEncapsulationBody`, which was `tunnelNestedBody`.
There is no `types.taggedExpression`: use `expression`, or `expressionOf` for
selected tags.

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

`expressionOf` covers tagged expressions only. Compose it with scalar types if
the option also accepts scalars:

```nix
type = lib.types.oneOf [
  lib.types.str
  lib.types.int
  (nftlib.types.expressionOf [ "payload" "meta" ])
];
```

An unknown tag, an empty list, or a tag that is not a string fails while
constructing the restricted type, with a `nix-nftypes: types.statementOf:` or
`nix-nftypes: types.expressionOf:` error. A value outside the restricted type
fails with the type's description, which names its tags, such as
`statement (one of: "match")`.

## DSL

### Fields and expressions

Common field leaves live under `dsl.fields`:

```nix
nftlib.dsl.fields.tcp.dport
nftlib.dsl.fields.ip.saddr
nftlib.dsl.fields.ct.state
nftlib.dsl.fields.meta.iifname
nftlib.dsl.fields.rt.mtu
```

Each leaf is an expression nft loads as written in some rule, though the rule
can need a particular table family or hook: `fields.rt.nexthop` loads in an
`ip` or `ip6` table, not in an `inet` one. A key that nft loads only with a
refinement has no leaf; its `expr` constructor builds it:

| Key                                                                                                                 | Refinement nft requires          | Example                                                   |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------- |
| every FIB result                                                                                                    | `saddr` or `daddr` among `flags` | `expr.fib { result = "oif"; flags = [ "saddr" "iif" ]; }` |
| the conntrack keys `saddr`, `daddr`, `proto-src`, `proto-dst`, `ip saddr`, `ip daddr`, `ip6 saddr`, and `ip6 daddr` | `dir`                            | `expr.ct { key = "saddr"; dir = "original"; }`            |
| every IPsec key                                                                                                     | `dir`                            | `expr.ipsec { key = "reqid"; dir = "in"; }`               |

`expr.fib`, `expr.ct`, and `expr.ipsec` throw, naming the builder, without
their Refinement. `expr.ct` also throws for a direction on a key nft reads none
for: only `l3proto`, `protocol`, `packets`, `bytes`, `avgpkt`, `zone`, and the
keys above take one. The error states the rule as the body's type:

```text
nix-nftypes: dsl.expr.fib: not of type `fib body with saddr or daddr among its flags'.
```

`validate` checks raw input against the same rules. A ct expression has no
`family` field: nft's JSON parser ignores one, and a key such as `ip saddr`
names its family. The text renderer refuses a raw ct `family`.

Use `expr.payload protocol field`, `expr.payloadRaw`, and
`expr.payloadTunnel` when no pre-built leaf exists. The other structural and
generated expressions also live under `dsl.expr`, including `concat`, `prefix`,
`range`, `set`, `setRef`, `map`, `numgen`, `jhash`, and `symhash`.
The binary operators sit there too: `expr.bitAnd`, `bitOr`, `bitXor`,
`shiftLeft`, and `shiftRight`, as in `expr.bitAnd fields.meta.mark 255`.

Every `dsl.expr` builder but `setRef` validates its body when called, against
the body `types.expression` takes for its tag, as the statement builders do
(see [Statements](#statements)). A wrong value, an unknown argument, or a
missing required one throws with an option path that starts with the builder,
such as `dsl.expr.ct.key`; a positional builder whose body is a list, such as
`expr.concat`, names the internal option `value`. A builder that takes one
attrset takes the fields of its body in `types.expressionBodies`, and builders
that build one form of a body take that form only: `expr.payloadRaw`,
`expr.payloadTunnel`, `expr.tcpOption`, and `expr.tcpOptionRaw`. `setRef`
checks its name itself.

`expr.elem` takes `val`, `timeout`, `expires`, and `comment`. nft lists an
element's `counter`, `quota`, `limit`, or `last` beside its value, but its JSON
parser ignores them, so `expr.elem` rejects them as unknown options, while
`types.expressionBodies.elemBody` keeps them for Read-back.

Top-level match helpers include:

- `eq`, `ne`, `lt`, `gt`, `le`, `ge`;
- `inSet`, `notInSet`;
- `hasAnyFlag`, nft's `in` operator, which matches when any of the given flags
  is set: `hasAnyFlag tcp.flags [ "syn" "ack" ]` is `tcp flags syn,ack`.

Together they cover nft's seven match operators. Each validates its match
statement when called, as the statement builders do (see
[Statements](#statements)), so `eq { bogus = 1; } 2` throws naming
`dsl.eq.left`. A caller that computes the operator writes the raw
`{ match = { op; left; right; }; }`, which rule validation checks.

`inSet` and `notInSet` take a list, a set expression, or a named-set
reference such as `"@trusted"`. A string without `@` throws and points to
`expr.setRef`: nft would match it as one value, such as a hostname.

`expr.set [ ... ]` creates an anonymous set. `expr.setRef "name"` returns the
reference string `"@name"`, the shape nft lists, for the right side of a
match. The map lookup is `expr.map key data`. Its data is a named map's name,
with or without its `@`, or an anonymous map. A list of key-value pairs
becomes the anonymous map `{ set = [ ... ]; }`, as `inSet` wraps a list in an
anonymous set, because nft rejects a bare list there. `vmap key data` takes
its data the same way:

```nix
expr.map fields.tcp.dport "ports"
expr.map fields.tcp.dport [ [ 22 1 ] [ 80 2 ] ]
vmap fields.tcp.dport [ [ 22 accept ] [ 80 drop ] ]
```

#### References to named objects

Every builder that references a named object takes the name with or without
its leading `@`, and emits the spelling nft's JSON parser looks up there:

| Position                 | Builders                                                                                                                            | Emitted                                                    |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| a set, map, or flowtable | `expr.setRef`, `expr.map`, `vmap`, `setStmt`, `mapStmt`, `flow`                                                                     | `"@name"`; nft reads a bare name as a hostname or a symbol |
| a stateful object        | the `.ref` of `counter`, `quota`, `limit`, `synproxy`, `ctCount`, `ctHelper`, `ctTimeout`, `ctExpectation`, `secmark`, and `tunnel` | the bare name; nft finds no object named `"@name"`         |

A stateful object's `.ref` also takes a map expression, which selects the
object by key. `inSet` and `notInSet` are the exception: their
right side need not be a set, so they take `"@name"` and throw on a string
without `@`.

### Statements

Verdicts are values:

```nix
accept
drop
continue
return
```

`jump target` and `goto target` carry a chain target. A verdict is also the
data of a `vmap`.

Most statement families are callable attrsets with named variants. Examples:

```nix
counter { packets = 0; bytes = 0; }
counter.ref "named_counter"
counter.auto
quota.ref (expr.map fields.tcp.dport "quota_by_port")
ctHelper.ref "ftp"

reject { type = "icmpx"; code = "admin-prohibited"; }
log { prefix = "DROP: "; level = "info"; }
limit { rate = 10; per = "minute"; burst = 5; }
```

`.ref name` references a named object, by its name or by a map expression
that selects one by key; it throws for any other attribute set. `ctHelper`,
`ctTimeout`, `ctExpectation`, `secmark`, and `tunnel` have no other form, so
calling one directly throws and points to its `.ref`. `.auto` is the
null-body form, such as `{ counter = null; }`, that `nft -j list --stateless`
prints; `counter`, `synproxy`, and `last` have it. A statement whose fields
are all optional takes `{ }` for its empty form, for example `log { }` or
`masquerade { }`.

`counter` has no `{ }` form. nft parses an inline counter only with both
`packets` and `bytes`, so `counter { }` and a counter with one of them throw.
`counter.auto` is the unseeded counter.

`last` has no `{ }` form either: nft rejects an empty body, so `last { }`
throws. `last { used = …; }` seeds the last-used time, and `last.auto` is the
unseeded form.

`reject` takes `{ type?; code?; }`: `type` is the answer, such as `"icmp"`,
`"icmpv6"`, the family-independent `"icmpx"`, or `"tcp reset"`, and `code` the
ICMP code, which JSON calls `expr`. `reject { }` sends nft's default answer.

The conntrack statements are `ctHelper.ref`, `ctTimeout.ref`, and
`ctExpectation.ref`, which assign a named ct helper, timeout, or expectation to
the connection, and `ctCount { val; inv?; }` or `ctCount.ref name`, which
matches on the number of connections. `secmark.ref` applies a named secmark and
`tunnel.ref` attaches a named tunnel.

Other top-level constructors include `snat`, `dnat`, `masquerade`, `redirect`,
`queue`, `synproxy`, `flow`, `meter`, `vmap`, `mangle`, `tproxy`, `fwd`, `dup`,
`last`, and `notrack`, which exempts the packet from connection tracking.
`notrack` is a statement, not a verdict: a `vmap` rejects it as data.

`snat`, `dnat`, and `tproxy` take `addr`, `port`, or both: the kernel refuses
an snat or dnat with neither, and nft an empty tproxy, so `snat { }` and
`tproxy { }` throw. A builder's other required fields are those its schema body
requires, such as `limit`'s `rate` and `per`, `fwd`'s `dev`, and `meter`'s
`name`, `key`, and `statement`.

Every statement builder and match operator validates its statement when
called, against the body `types.statement` takes for its tag, as command
builders do. A statement is then checked wherever it goes, in a raw command
passed through `dsl.ruleset` too. A field's error is the module system's,
without the `nix-nftypes:` prefix, and its option path starts with the
builder:

```text
A definition for option `dsl.log.level' is not of type `null or one of "emerg", …'.
The option `dsl.redirect.addr' does not exist.
The option `dsl.limit.per' was accessed but has no value defined.
```

The option path need not name the field as the DSL spells it. A field takes
its JSON key before validation, so a renamed field appears by its JSON
spelling, as in `dsl.quota.val_unit` for `valUnit`. A builder that takes its
body positionally names the body's JSON field, as in `dsl.mangle.key` or
`dsl.eq.left`, or, where the body is a single expression, the internal option
`value`: `resetStmt` errors name `dsl.resetStmt.value`, and a `.ref` given a
map expression names its key as `dsl.counter.ref.value.map.key`.

The builders' own checks carry the prefix. A body that isn't an attribute set
throws, such as
`nix-nftypes: dsl.log: expected an attribute set of fields, got a string`, and
so does a body the schema rejects as a whole, such as
``nix-nftypes: dsl.snat: not of type `snat/dnat body with addr or port'.``.

The statement tags named `set`, `map`, and `reset` would collide with the
`expr.set` and `expr.map` constructors and the `reset.<kind>` command builders,
so their DSL names are `setStmt`, `mapStmt`, and `resetStmt`. `resetStmt expr`
resets the stateful data an expression selects, such as a TCP option:
`resetStmt (expr.tcpOption { name = "sack"; })`. Like `flow`, `setStmt` and
`mapStmt` take the set, map, or flowtable name with or without its leading `@`.
`setStmt` takes the `element` it adds, and `mapStmt` takes the `key` and `data`
it writes. `flow` takes the flowtable alone, because nft's only flow operation
is `add`:

```nix
setStmt { op = "add"; element = fields.ip.saddr; set = "blocked"; }
mapStmt { op = "update"; key = fields.ip.saddr; data = 1; map = "marks"; }
flow "ft"
```

The DSL has no `xt` builder; `types.statementBodies.xtBody` types the
Read-back ([`spec-coverage.md`](spec-coverage.md#3-read-backinput-asymmetries)).

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
      [ (nftlib.dsl.inSet nftlib.dsl.fields.ip.saddr "@trusted") nftlib.dsl.accept ]
    ];
  };
}
```

Recognized table-body keys are:

- table options: `flags`, `comment`;
- `chains`;
- `sets`, `maps`, `flowtables`, `counters`, `quotas`, `limits`, `ctHelpers`,
  `ctTimeouts`, `ctExpectations`, `ctCounts`, `secmarks`, and `synproxies`.

A set or map takes its elements in its own body, as `sets.<name>.elements`.
To add elements to a set defined elsewhere, put `add.element` in a
`dsl.ruleset` after the set.

A quota object takes its threshold in `bytes`. `val`, the quota statement's
word, throws and points to `bytes`, in a Table tree's `quotas` and in
`add.quota` and `create.quota` alike.

An unknown key throws, listing the keys a Table tree takes, and a kind's
singular name points to its plural, as in ``unsupported key(s): set; a Table
tree takes flags, comment, chains, …; write `sets` for `set` ``.

`dsl.table` marks the tree with `_type = "nix-nftypes.tableTree"`, the nixpkgs
convention for a value's kind. Cleaning strips the marker, so it never reaches
JSON or text. A body's own `_type` throws, since the marker would replace it.

Expansion order is table, chains, named objects, then rules. Among
named objects, stateful objects come first, so a set or map element can name
one: counters, quotas, limits, ct helpers, ct timeouts, ct expectations,
secmarks, synproxies, and ct counts. The other kinds follow alphabetically.
Object and chain names are emitted in sorted order; rule order remains the
source-list order. This covers dependencies made explicit by the table tree;
dependencies hidden in raw nested bodies remain the caller's responsibility.

A rule entry is either a non-empty statement list or an attrset with a
non-empty `statements` list and an optional `comment`. The list order is the
rule order, so an entry's `index` throws, as in
``nix-nftypes: dsl.table inet.t: chains.input.rules.1.index: a Table tree lists
a chain's rules in order, so a rule takes no `index`; …``. To place a rule,
use `add.rule` or `insert.rule` with its `index`. Any other entry throws, naming its path, such as `chains.input.rules.0`: write a single
statement as a list, `[ dsl.drop ]`, not as the bare `dsl.drop`.

A Table tree adds its objects, so no body in it takes a `handle`: not the
table, a chain, a rule entry, or a named object. Each throws at the handle, as
in `nix-nftypes: dsl.table inet.t: chains.input.handle: nft ignores a handle on
add, create, and rename, …`.

A field's error inside a Table tree is the module system's, and its option
path starts with the tree, which the module system quotes:

```text
A definition for option `"dsl.table inet.fw".chains.input.prio' is not of type `null or signed integer'.
```

### Naming and argument conventions

Every DSL field name is camelCase, and each field has one spelling. The DSL
renames it where JSON uses hyphens or underscores or runs words together, for
example `queueThreshold` to `queue-threshold`, `gcInterval` to `gc-interval`,
`rateUnit` to `rate_unit`, `typeFlags` to `type_flags`, and `newName` to
`newname`. A field that holds statements, elements, or a key takes the DSL word
for what it holds:

- Named sets and maps take `elements` and `statements` for the JSON `elem` and
  `stmt`.
- `setStmt` takes `element` and `mapStmt` takes `key` for the JSON `elem`, and
  both take `statements` for `stmt`.
- A rule takes `statements` for `expr`, and `meter` takes one `statement` for
  `stmt`.

A field whose JSON key names something other than what it holds also takes the
DSL word: `reject` takes `code` for `expr`, which holds the ICMP code, and a
map takes `dataType` for `map`, which holds the data type of its values, as in
`maps.m = { type = "ifname"; dataType = "verdict"; }`. Other fields keep nft's
word: a chain or flowtable's `dev` takes one device or a list. The same renames apply to statements,
table-tree objects, and command builders, and in each a JSON spelling throws,
pointing to the DSL name:

```text
nix-nftypes: dsl.add.limit: rate_unit: is the JSON spelling; write `rateUnit`
```

A body is an attrset of fields, never a module. A string in a body position,
such as `create.counter "c1"`, throws naming its path, and a string in a name or
reference position, such as `synproxy.ref "/sp1"`, is a name. Module keys such
as `imports` are unknown fields, and `_module` throws.

A builder takes positional arguments only when every argument is required and
there are at most two, as in `eq left right`, `vmap key data`, `expr.map key
data`, `expr.payload protocol field`, `expr.prefix addr len`, and
`counter.ref name`. Every other builder takes one attrset.
`dsl.table family name body` is the exception; it mirrors nftables'
`table inet filter { … }` syntax. The rule covers `dsl` builders: the
compatibility helpers look values up in the compatibility tables and take
their three keys positionally, as in
`compatibility.priorityValue family hook priority`.
See [ADR 0009](adr/0009-dsl-naming-and-argument-conventions.md).

### Commands

| API                               | Notes                                                                                |
| --------------------------------- | ------------------------------------------------------------------------------------ |
| `add.<kind>`                      | 16 add-object kinds; `add.rule` adds a standalone rule                               |
| `create.<kind>`                   | 15 object kinds; `rule` is excluded                                                  |
| `delete.<kind>`, `destroy.<kind>` | 13 add-object kinds; not `ctCount`, `ctTimeout`, or `ctExpectation`                  |
| `flush.<kind>`                    | table, chain, set, map, meter, or ruleset; nftables has no `flush flowtable` command |
| `list.<kind>`                     | table, chain, set, map, counter, quota, limit, ctHelper, secmark, or meter           |
| `reset.<kind>`                    | counter, quota, set, map, or element                                                 |
| `insert.rule`, `replace.rule`     | rule-only commands                                                                   |
| `rename.chain`                    | chain-only rename                                                                    |

Each `<verb>.<kind>` builder takes one object body. `flush.ruleset { }` flushes
every family, and `flush.ruleset { family = "ip"; }` flushes one.

A builder returns one command holding only the fields given, under their JSON
keys, as a table tree's commands do: `add.limit { family = "inet"; table = "t";
name = "l"; rate = 10; per = "second"; }` returns those five fields under
`add.limit`, without a `null` for an unset field. Render a command inside a
ruleset: `toJson (dsl.ruleset [ (dsl.add.limit { … }) ])`.

In one batch, nft runs a `reset` of a counter, quota, set, map, or rule only as
the last command: followed by any other command, it resets nothing, and nft still
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
- A body takes `handle` only where nft reads it: in Read-back, in a Selector,
  and in `insert.rule` and `replace.rule`. Every `add.<kind>`,
  `create.<kind>`, and `rename.chain` throws on one, at the handle, and points
  to Read-back, as in `nix-nftypes: dsl.add.table: handle: nft ignores a
handle on add, create, and rename, …`; `validate` rejects one in those
  commands. nft ignores the handle there, so JSON kept it and text dropped it.
- `replace.rule` requires the `handle` of the rule it replaces.
- On `add rule`, nftables 1.1.6's JSON parser ignores a handle and appends the
  rule, while 1.1.7 and text place the rule after the rule with that handle.
  Place a rule with `index`, or with `insert.rule`, whose `handle` puts it
  before that rule; see
  [`spec-coverage.md`](spec-coverage.md#rule-handles-on-add-rule).
- `add.rule`, `insert.rule`, and `replace.rule` require statements, a
  non-empty `statements` list, as a table tree's rule entries do. Without
  them, the builder throws, naming the command, such as `add.rule`.
- `rename.chain` requires `newName`.

`delete`, `destroy`, `list`, `flush`, and `reset` select an object by `family`,
`table`, and `name`, and demand no field that nft ignores for the verb: a set's
or map's datatypes, a limit's rate, a flowtable's hook, and a synproxy's `mss`
and `wscale` are optional there. `types.objectBodies` holds these selection
bodies, such as `selectSetBody`. Every `delete.<kind>` but `delete.rule`
requires `name`, though nft also deletes most kinds by `handle` alone
([`spec-coverage.md`](spec-coverage.md)); `destroy.<kind>` requires it in nft
too.

A rule is selected by its `chain` and `handle`, which `delete.rule` and
`destroy.rule` require as a positive integer: nft takes handle 0 as none, and
the kernel then deletes every rule in the chain.

## Renderers

Every renderer cleans its input before rendering it ([Cleaning](#cleaning)),
and names itself in its errors, as in `nix-nftypes: toTextBlock: `.

`toJson`, `toText`, and `toTextPretty` take only a ruleset,
`{ nftables = [ … ]; }`, and throw on anything else. A lone command throws, and
so does a `dsl.table` value passed alone or among the `nftables` commands, and
a ruleset nested among them, which nft rejects; each error asks for
`dsl.ruleset`. Build a ruleset with `dsl.ruleset [ … ]`, which takes commands,
Table trees, and rulesets, expands each tree into commands, and splices each
ruleset's commands in place.

These three renderers give a rule without `expr` the empty list: nft's JSON
parser requires the key on a rule even where it ignores it, as for
`destroy.rule`, so a raw rule command may leave it out.

### `toJson ruleset`

Returns compact JSON via `builtins.toJSON`. Use the result with `nft -j -f`.

### `toText ruleset` and `toTextPretty ruleset`

Render imperative nftables commands. The compact form minimizes whitespace;
the pretty form uses readable multi-line blocks and puts a blank line where
the commands move to another table. Both are pure Nix.

Every line ends with a newline, the last included, so renders concatenate:
`toText a + toText b` loads as both rulesets. An empty ruleset renders as
`""`.

### `toTextBlock tableNode` and `toTextBlockPretty tableNode`

Render only the contents of one `dsl.table` node. These functions omit the
outer table declaration, keep the table's `flags` and `comment` as the first
declarations, and place rules inside their chain blocks. A Table tree's rules
take no `index`, so every tree renders in both forms. Passing a full ruleset or
a raw command is an error.

Every declaration ends with a newline, the last included, and a table with no
declarations renders as `""`.

The JSON renderer is authoritative when JSON and text grammar capabilities
differ. See [`text-coverage.md`](text-coverage.md).

## Cleaning

Cleaning, which each renderer applies to its input, recursively removes:

- internal module markers such as `_type`;
- unset `null` fields from ordinary multi-key attrsets.

It preserves significant tagged-null forms such as `{ accept = null; }` and
`{ ruleset = null; }`, also when the value carries a `_type` marker.

Cleaning is not validation.

## Reference data

`nftlib.enums.<name>` exposes the same value list used by each enum type.
Examples include `family`, `hook`, `matchOperator`, `metaKey`, `ctKey`,
`rtKey`, `fibResult`, `setFlag`, and `tunnelType`. `byteUnit` holds nft's byte units,
`bytes`, `kbytes`, and `mbytes`, which type a limit's `burst_unit` and a
quota's `val_unit` and `used_unit`; `limitRateUnit`, which types a limit's
`rate_unit`, adds `packets`.

`nftlib.compatibility` holds the static tables and the helpers that look
placements and priorities up in them. The tables are:

- `hooksByFamily`;
- `familiesByChainType`;
- `hooksByChainType`;
- `prioritiesByFamily`, the symbolic priorities nft accepts at each hook of
  each family, indexed by family and hook: `prioritiesByFamily.bridge.input`
  is `{ filter = -200; }`;
- `hooksWithOifname`.

`prioritiesByFamily` holds only what nft accepts, as
`std_prio_family_hook_compat` in nftables' `src/rule.c` decides:

| Family        | Symbols                                                                                                                       |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| ip, ip6, inet | `raw`, `mangle`, `filter`, and `security` at every hook; `dstnat` at prerouting and output; `srcnat` at input and postrouting |
| bridge        | `filter` at every hook; `dstnat` at prerouting, `out` at output, and `srcnat` at postrouting                                  |
| arp, netdev   | `filter`                                                                                                                      |

The helpers are:

- `priorityValue family hook priority` converts a symbolic priority to its int
  at the hook, and passes an int through. It resolves a bare symbol only, so
  add an offset with Nix arithmetic:
  `priorityValue "ip" "input" "filter" + 10`.
- `priorityName family hook priority` is the reverse: it maps an int to the
  symbol nft accepts for it at the hook, and otherwise returns the int, as nft
  lists it. `priorityName "ip" "prerouting" (-100)` is `"dstnat"`, but
  `priorityName "ip" "input" (-100)` is `-100`. A symbol passes through.
- `chainTypeFor family hook priority` classifies the project's conventional
  chain type policy. NAT priorities map to `nat` and the `mangle` priority to
  `route`, unless `validChainPlacement` rejects that type at the hook, in the
  family; every other placement maps to `filter`. So
  `chainTypeFor "bridge" "postrouting" 300` (bridge `srcnat`) and
  `chainTypeFor "ip" "prerouting" "mangle"` return `filter`. An int counts as a
  symbol only where nft accepts the symbol, so
  `chainTypeFor "ip" "input" (-100)` is `filter` too.
- `validChainPlacement family chainType hook` checks the static family,
  chain-type, and hook tables. A hook the family lacks is an invalid
  placement: `validChainPlacement "arp" "filter" "forward"` is `false`.

Every helper throws, naming the helper, on a family, chain type, or hook
outside its table, so a typo doesn't read as an invalid placement. The three
priority helpers also throw on a hook the family lacks and on a symbol nft
rejects at the hook, as nft does:

```text
nix-nftypes: compatibility.priorityValue: family 'netdev' has no priority 'mangle' at hook 'ingress'. Valid priorities: any int, filter.
```

These helpers do not inspect kernel versions, loaded modules, devices, or
runtime state. An `inet`/`netdev` ingress chain can still require `dev`, for
example, even when the static triple is valid.
