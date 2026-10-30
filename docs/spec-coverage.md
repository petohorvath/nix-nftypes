# Schema coverage

This document states what `lib/schema/` models, what evidence checks it, and
where it intentionally differs from nftables. It is a current-state reference,
not a history of earlier fixes.

## Compatibility authority

The authorities are the nftables packages in the `nixpkgs` flake input, locked
to the stable NixOS branch. The project policy reruns the checks with its
stable and unstable pins overriding `nixpkgs`.

For each package set, source checks use `pkgs.nftables.src` plus the
derivation's complete downstream patch set. Live checks use that same package
set's `nft` binary. There is no independent Netfilter Git input.

The parser (`src/parser_json.c`) defines accepted JSON input. The serializer
(`src/json.c`) defines read-back shapes. The libnftables JSON manual is useful
reference material but is not complete enough to be the sole authority.

## Modelled surfaces

| Surface                    | Current schema                                                                                                                                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Commands                   | `add`, `replace`, `create`, `insert`, `delete`, `destroy`, `list`, `reset`, `flush`, `rename`                                                                                                                                               |
| Add objects                | 16 singular object kinds; `tunnel` is excluded because nftables mishandles it                                                                                                                                                               |
| Create objects             | 15 kinds; `rule` is excluded because nftables rejects `create rule`                                                                                                                                                                         |
| Delete and destroy objects | 13 kinds; `ct count`, `ct timeout`, and `ct expectation` are excluded because nftables mishandles them. A set, map, limit, or flowtable needs only its name; `delete` takes a named object's handle in place of its name, but a ct helper's |
| Replace and rename objects | a rule with its `handle`; a chain with its `newname`                                                                                                                                                                                        |
| List objects               | table, chain, set, map, counter, quota, limit, ct helper, secmark, and meter; nftables has no singular `list` of the other kinds, and mishandles a `ct timeout` or `ct expectation`                                                         |
| Listed objects             | bare objects in a ruleset, as `nft -j list` emits: 16 add objects plus `metainfo`, `meter`, and `tunnel`                                                                                                                                    |
| Flush objects              | table, chain, set, map, meter, ruleset                                                                                                                                                                                                      |
| Reset objects              | counter, quota, rule, set, map, element                                                                                                                                                                                                     |
| Statements                 | 37 tagged forms                                                                                                                                                                                                                             |
| Tagged expressions         | 34 tags, plus scalar and bare-list branches in the full `expression` type                                                                                                                                                                   |

The schema also includes parser behavior missing or incomplete in the manual,
including:

- `last`, `flow`, `tproxy`, `reset`, `secmark`, and `tunnel` statements;
- `secmark`, `synproxy`, and `ct count` objects, and tunnel objects as
  Read-back;
- stateful-object references selected by a map (`counter`, `quota`, `limit`,
  `synproxy`, and `ct count` with `name <key> map { … }`);
- inner-header payloads, raw TCP option forms, tunnel payloads, and XFRM/tunnel
  metadata expressions;
- parser-only enum values such as `rt.ipsec`, `fib.check`, and OS fingerprint
  `version`;
- list-or-singleton device fields;
- nullable handles and other serializer fields needed by selected read-back
  cases.

`ct count` objects and `ct count` object references require nftables 1.1.7 or
later; earlier versions reject them. The locked `nixpkgs` carries an earlier
nftables, so no live check exercises them yet. The corpus check covers their
statement shapes when it runs against a package set with 1.1.7, as the shared
policy's unstable pin does. Add live integration cases once the locked
`nixpkgs` carries 1.1.7.

A map statement with per-element statements (`stmt`, such as
`update @cache { ip saddr counter : 42 }`) loads through JSON from nftables
1.1.7; the JSON parser of 1.1.6 crashes on it. Text loads it on both. The
schema accepts it, as nftables 1.1.7 does (ADR 0010), and the parse check
expects the crash on earlier versions.

## Known differences

“Schema coverage” does not mean byte-for-byte equivalence with every parser
branch. Differences fall into four groups.

### 1. Parser input accepted but schema rejected

The packaged nftables statement corpus currently exercises 2 baselined
categories:

| Category         | Schema limitation                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| unary negation   | match operator `!` is not in the operator enum                                                      |
| partial synproxy | a flags-only synproxy statement is rejected because the schema requires `mss` and `wscale` together |

The executable baseline is `knownDivergences` in
[`tests/helpers/corpus-drift.nix`](../tests/helpers/corpus-drift.nix). A
statement matching no known category fails the check, and so does a category
no statement matches any more; prune it from the baseline when its gap is
fixed.

Additional command and selector differences are not statement-corpus shapes:

- nftables has plural `list` selector forms such as `tables`, `chains`, and
  `sets`, plus plural `reset` selector forms; these parser-accepted command
  forms are not modelled;
- a Selector takes `name` or `handle` exactly where the parser reads one:
  `delete` of a table, chain, set, map, flowtable, or stateful object but a
  ct helper takes exactly one of them, and every other Selector but a rule's
  requires the name, as the parser does; with a name, the parser never reads
  the handle, so the schema rejects both. The schema requires the handle to
  be positive, though the parser takes handle 0 as no handle: `delete table`
  with handle 0 deletes every table of the family (nftables 1.1.6). The
  `delete-by-handle` Integration case deletes each kind by handle;
- a Selector rejects every field the parser ignores for its verb, such as a
  set's `elem` on `delete set`, which deletes the whole set instead of the
  elements, a Known difference that the `delete-set-elem-deletes-whole-set`
  live test asserts nft still shows (nftables 1.1.6 and 1.1.7);
- the schema requires a positive `handle` on a rule delete or destroy, though
  the parser takes handle 0: it reads 0 as no handle, and the kernel then
  deletes every rule in the chain, a Known difference that the
  `delete-rule-handle-zero-deletes-every-rule` and
  `destroy-rule-handle-zero-deletes-every-rule` live tests assert nft still
  shows (nftables 1.1.6 and 1.1.7).

Use direct JSON only when one of these parser forms is required, and validate
it with the real packaged parser.

#### Commands nft mishandles

The schema rejects these commands, which nft accepts but runs as something
else, measured on nftables 1.1.6 and 1.1.7 (ADR 0010):

| Command                                    | nft result                                                                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `delete` or `destroy` of a ct expectation  | deletes the whole table and exits 0                                                                                    |
| `list` of a ct expectation                 | lists the whole table                                                                                                  |
| `delete` of a ct timeout                   | fails with `Invalid argument`                                                                                          |
| `destroy` of a ct timeout                  | fails, reported as unsupported                                                                                         |
| `list` of a ct timeout                     | aborts on an assertion                                                                                                 |
| `delete` or `destroy` of a ct count        | 1.1.7 aborts on an assertion; 1.1.6 has no ct count object                                                             |
| `add` or `create` of a tunnel              | loads the `dport` as the tunnel's `sport` and no `dport`; a missing port, `ttl`, or `tos` loads an uninitialised value |
| `delete`, `destroy`, or `list` of a tunnel | aborts on an assertion                                                                                                 |

For delete, list, and destroy, nft's JSON parser passes the kernel object
number as its command object type, so a ct expectation is taken for a table, a
ct timeout for a chain, and a tunnel for nft's rules type, which evaluation
doesn't expect. nftables 1.1.7's delete evaluation has no `return` after its ct
count case, which reaches its `BUG()`; text input aborts the same way. The
tunnel parser assigns `dport` to the tunnel's `sport` and leaves each field
that the input omits uninitialised.

The cases of `integration-nft-misbehaviour` assert that nft still mishandles
each command, so a fixed nft fails them and the command can return. Add, create,
and Read-back of the ct objects are unaffected. A tunnel validates only as
Read-back, a bare listed object in `types.ruleset`; the DSL builds no tunnel,
and the text renderer refuses one.

#### Chains with part of a placement

A chain body sets `type`, `hook`, and `prio` together, a base chain, or none of
them, a regular chain. nft's JSON parser reads the three as one optional group,
so it loads a chain with only some of them as a regular chain whose rules never
see packets, in nftables 1.1.6 and 1.1.7. The schema rejects such a chain, which
is stricter than the parser (ADR 0010). The parser reads `dev` and `policy`
only in the same group, so it loads a regular chain without them, while nft's
text rejects one ("Operation not supported" for a policy, "No such file or
directory" for devices); the schema takes them on a base chain only. The eight
`chain-*` cases of `integration-nft-misbehaviour`, one for each partial
placement and one each for `dev` and `policy` without one, assert that nft
still loads a regular chain.

#### Handles on `add`, `create`, and `rename`

nft's JSON parser ignores a `handle` on `add` and `create` of every kind but a
rule, and `rename chain` reads only the family, table, name, and new name. The
object loads with the handle the kernel assigns, and text has no spelling for
one, so JSON kept the handle and text dropped it. The schema rejects a handle
in these bodies and in every Table-tree body (ADR 0009, ADR 0010), and the
error points to Read-back, where nft lists the handle. The `add-handle-ignored`
case of `integration-nft-misbehaviour` asserts that nftables 1.1.6 and 1.1.7
still ignore the handle on an added table, chain, set, counter, and flowtable,
and on a created quota. A handle stays in Read-back, in a Selector, and in
`insert rule` and `replace rule`, which nft reads it in.

#### Rule handles on `add rule`

`add rule` takes no `handle`. nftables 1.1.6's JSON parser ignores one and
appends the rule, so the schema rejects the field there (ADR 0010), and
`add.rule` and table-tree rules throw at it. Place a rule with `index`, or
with `insert`. Measured on nftables 1.1.6 and 1.1.7, with rules 2, 3, and 4 in
a chain:

| Command with `handle = 3`     | JSON                                                                      | Text                                     |
| ----------------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| `add rule`                    | 1.1.6 ignores the handle and appends the rule; 1.1.7 adds it after rule 3 | after rule 3                             |
| `insert rule`                 | before rule 3                                                             | before rule 3                            |
| `replace rule`                | replaces rule 3                                                           | replaces rule 3                          |
| `delete rule`, `destroy rule` | deletes rule 3                                                            | deletes rule 3                           |
| a listed `rule`               | ignores the handle and appends the rule                                   | no such form: text leaves the handle off |

With a handle no rule has, every command but `destroy` fails with `No such
file or directory`, in JSON and text; `destroy` exits 0, and 1.1.6's JSON
`add rule` and a listed rule append the rule. A listed rule keeps its handle
in the schema, and the text renderer leaves it off, so a Read-back with rules
loads as text what it loads as JSON. The text renderer refuses a handle on `add
rule`, which no text form loads as both versions' JSON does (see the
[text coverage](text-coverage.md#fields-json-input-ignores)). The
`add-rule-handle-ignored-on-json` case of `integration-nft-misbehaviour` asserts
that 1.1.6 still ignores the handle on `add rule`, and that 1.1.7 still adds
the rule after it.

#### Resets before another command

In one batch, nft runs a `reset` of a counter, quota, set, map, or rule only
as the batch's last command, in nftables 1.1.6 and 1.1.7, through JSON and
text. Followed by any other command, another reset included, it resets
nothing, and nft still exits 0; a set or map reset followed by another set or
map reset fails with `No such file or directory` instead. A `reset` of an
element runs anywhere. `types.ruleset` rejects a ruleset with a reset of a
counter, quota, set, map, or rule before its last entry, which is stricter
than the parser (ADR 0010). Give each such reset a ruleset of its own, or put
it last. The `reset-runs-only-the-last` and
`reset-before-another-command-resets-nothing` cases of
`integration-nft-misbehaviour` assert that nft still drops such a reset.

### 2. Schema intentionally more permissive

Some parser conditions depend on large lookup tables or relationships between
fields. The schema checks useful local types but leaves the final condition to
`nft`:

- FIB flags have parser-level mutual-exclusion rules;
- tunnel source and destination fields must form one same-family pair;
- set/map datatypes are strings rather than exhaustive enums;
- `concat` does not enforce its minimum of two operands;
- `mangle.key` takes the keys nft's parser takes there, `ip option` and
  `sctp chunk` included, though the kernel refuses to change either with
  `Operation not supported`;
- `snat`, `dnat`, and `tproxy` in an `inet` table need an address family for
  an address or an address map, as `family = "ip"`, unless an earlier match in
  the rule, such as `ip saddr` or `meta nfproto ipv4`, fixes it: nft fails
  without one, from JSON and text alike, with
  ``specify `dnat ip' or 'dnat ip6' in inet table to disambiguate``. A port
  alone needs none. The schema would have to follow the protocol context
  through the rule, so it leaves the condition to `nft`;
- tunnel `type` and its nested tunnel-parameter body are typed independently,
  so agreement between them remains a parser check;
- some NAT, reject, and object-field combinations are meaningful only in
  specific contexts;
- a secmark object's context must name a security context the kernel's
  SELinux knows, so a secmark object, and any rule that references one, loads
  only on an SELinux kernel. The test VMs' kernels have none, so the reach
  check names the `secmark` statement and the add, create, delete, and list
  secmark commands as Named exclusions. Destroying an absent secmark loads
  anywhere;
- a `dccp option` match needs the kernel's DCCP support, which Linux 6.16
  removed, so a newer kernel refuses the rule with `Operation not
supported`. The reach check names the `dccp option` expression as a Named
  exclusion, and the parse check expects the refusal from Linux 6.16 on;
- `resetObject` accepts `rule`, but nft's JSON path fails `reset rule` with
  `Operation not supported`. The DSL has no builder for it, and the reach
  check names it as a Named exclusion.
- a ruleset may hold several `list` commands, but in one batch they share
  nft's object cache, which nftables 1.1.6 and 1.1.7 fill for one of them.
  Depending on the order, a set or map lists without its elements, as after
  `list chain`, or a `list set` before a `list map` fails with `No such file
or directory`. Give each `list` whose output matters a ruleset of its own;
- a named payload body takes any protocol and field string. `expr.payload`
  takes only those of `enums.payloadFieldsByProtocol`, which leaves out two
  forms nft's parser takes: `l4proto` on `ip`, `ip6`, `gre`, and `gretap`,
  which loads as the header bits at offset 0, so `ip l4proto 6` loads as
  `ip version 0 ip hdrlength 6`, and the `vxlan` and `geneve` fields, which
  load only in the tunnel form. The `payload-l4proto-loads-header-field` case
  of `integration-nft-misbehaviour` asserts that nft still loads `ip l4proto`
  so.

A schema-successful value is therefore not proof that a particular kernel will
accept the resulting ruleset. Live-parser and real-load tests remain necessary.

### 3. Read-back/input asymmetries

`xt` is modelled because listed legacy rules can contain it, but the JSON parser
rejects `xt` as new input and instructs callers to use `iptables-nft`. No
Integration case can load it, so the reach check names the `xt` statement as a
Named exclusion. The DSL has no `xt` builder.

A set or map `comment` is a Read-back shape: nft lists it, but its JSON parser
ignores it on input, in nftables 1.1.6 and 1.1.7. The schema accepts it, JSON
input loads the set or map without it, and the text renderer refuses it, because
text would load it. The `set-comment-ignored-on-json` case of
`integration-nft-misbehaviour` asserts that nft still ignores it.

Element statements are a Read-back shape too: nft lists each element's stateful
statement as a `counter`, `quota`, `limit`, or `last` key beside its `val`, but
its JSON parser reads only `val`, `timeout`, `expires`, and `comment`, in
nftables 1.1.6 and 1.1.7. JSON input drops the statements, both those keys and a
`stmt` list, while text loads them when the set declares the same statement.
Read-back accepts the listed keys through `elemReadBackBody`, input commands
reject them through `elemBody`, no element takes a `stmt` list, and the text
renderer refuses them. Set-level statements load identically through JSON and
text, and give each element its own instance. The `element-statements-ignored-on-json` case of
`integration-nft-misbehaviour` asserts that nft still ignores them.

A ct expression's `family` is not a Read-back shape: nft's JSON parser
ignores it on input and its printer never writes it (`json_parse_ct_expr` and
`ct_expr_json`, nftables 1.1.6). nft lists `ct original ip saddr` as the key
`ip saddr` with a direction. The schema has no ct `family`, and the text
renderer refuses one in raw input. In an inet table nft refuses a ct `saddr`
or `daddr` match ("use ip saddr or ip6 saddr instead"); the schema can't see the
table's family, so it leaves that to nft. Write `ip saddr` or `ip6 saddr` there.

A ct helper, timeout, or expectation accepts `l3proto = "inet"`, which nft
lists for one in an inet table that names none. Recent kernels refuse an inet
ct expectation unless its `l3proto` is `ip` or `ip6`.

Handles and metadata emitted by `nft -j list ruleset` are accepted where the
current body model needs them. The top-level ruleset union accepts both command
wrappers and bare listed objects. This does not imply that every possible
serializer output has been observed.

### 4. JSON and text are separate surfaces

A schema value can be valid JSON input while lacking a usable text spelling.
Text support and exclusions are tracked separately in
[`text-coverage.md`](text-coverage.md).

An added, inserted, or replaced rule with no statements is one such value. nft's
JSON parser loads it as an empty rule, so the schema accepts it, while nft's text
grammar has no spelling for it, so the text renderer refuses it.

## Validation boundaries

Nix module validation is strict about declared fields, enum membership, and
primitive types. It is applied when callers run `nftlib.validate` or use
`nftlib.types` in their own options, and when the DSL expands its own
structured nodes.

The renderers do not run arbitrary raw values through `types.ruleset`.
Likewise, raw attrsets inserted into `dsl.ruleset` are escape hatches and are
passed through. See [`api.md`](api.md) for an explicit `validate` example.

## Executable evidence

| Check                                        | What it proves                                                                                                                                                                                                                                                                                | Important limit                                                                                                                                                         |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nix-unit`: schema and focused safety suites | Nix-level accepted/rejected values and renderer regressions                                                                                                                                                                                                                                   | hand-written cases cannot discover unknown upstream syntax                                                                                                              |
| `nix-unit`: reach check                      | every statement tag, expression tag, and command/object pair the schema accepts appears in an Integration case whose JSON loads                                                                                                                                                               | each gap is a pending entry naming its open ticket, or a Named exclusion naming its Known difference, in `tests/fixtures/reach.nix`; an entry that a case reaches fails |
| `integration-dsl`                            | every Integration case's JSON passes the package set's `nft -c -j -f`; each negative case, one wrong value such as an unknown enum value or a port of 65536, is rejected by both nft and `types.ruleset`, which accepts the corrected value                                                   | check mode is not a real load; negative cases are samples, not every field                                                                                              |
| `integration-parse-check`                    | every expected JSON value in the DSL parity suite and every Field leaf pass `nft -c -j -f` in a minimal context                                                                                                                                                                               | expected rejections are listed with their ticket or Known difference and must still fail                                                                                |
| `integration-chain-placement`                | a base chain loads at exactly the family, chain type, and hook placements `compatibility.validChainPlacement` accepts, over all 126; a filter chain loads at exactly the priority symbols `compatibility.prioritiesByFamily` lists for its family and hook, at the listed value, over all 175 | placements at priority 0 only, and symbols in filter chains only; an ingress or egress chain gets a dummy device, which `validChainPlacement` doesn't model             |
| `integration-nftables-source-provenance`     | source analysis uses the selected package source and patches                                                                                                                                                                                                                                  | provenance, not semantic coverage                                                                                                                                       |
| `integration-nftables-enum-extraction`       | each extracted parser token table matches the model's list, and holds at least its count at the lock                                                                                                                                                                                          | extractor covers enumerated patterns, not every conditional branch                                                                                                      |
| `integration-nftables-corpus`                | every upstream corpus record parses, and none has an unclassified schema rejection                                                                                                                                                                                                            | 2 categories are explicitly baselined                                                                                                                                   |
| `integration-nftables-roundtrip`             | every command emitted by the real-loaded Integration cases validates as `types.ruleset`; each listing holds an object besides `metainfo`                                                                                                                                                      | sampled serializer coverage                                                                                                                                             |
| `integration-nftables-tooling-selftest`      | injected source/corpus/token defects make the drift checks fail                                                                                                                                                                                                                               | tests the tooling's chosen fault classes                                                                                                                                |

All package-set-dependent checks are instantiated from `nixpkgs` on each Linux
check system. CI runs the checks, including the VM tests, with the locked
input and with the policy's stable and unstable pins; the policy's Pin-bump
tests also run them with proposed pins before their release.

## Updating the schema

For a confirmed parser or serializer change:

1. inspect the exact patched source from the affected nixpkgs input;
2. add a failing focused schema test;
3. update the schema and the matching DSL/text surface when applicable;
4. run the relevant live parser and read-back checks with the locked `nixpkgs`
   and, overriding it, with the policy's unstable pin;
5. remove or narrow any corpus baseline that no longer matches;
6. update this document only with the remaining current differences.
