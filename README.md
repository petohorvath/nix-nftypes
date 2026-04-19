# nix-nft-types

Typed Nix bindings for nftables. Rulesets are built as structured Nix values, type-checked at evaluation time, rendered to JSON, and fed to `nft -j -f`.

Authoritative reference: **nftables 1.1.6** (upstream commit `0960e9001ed372140dee853733ca2c7464bdb1c7`, 2026-04-18). Every field, enum, and structural decision in this library is derived from that revision.

## Why this exists

Writing nftables rulesets is error-prone. The classic `nft` syntax is stringy, has no static checking, and typos only surface when the ruleset hits the kernel. Generating that syntax from Nix makes things worse — string concatenation, shell-escaping footguns, no structural composition beyond `lib.concatStringsSep`. The `nft -j` JSON interface is more robust, but hand-writing that JSON is miserable, and the `libnftables-json(5)` man page that should describe what is legal is incomplete and in places actively wrong. Existing Nix firewall libraries either rebuild `nft` syntax with ad-hoc types, or type a thin slice of the JSON schema based on the man page — which is not what `nft -j -f` actually accepts.

This library closes that gap: a full, strict, source-of-truth type system for nftables rulesets in Nix, covering everything the JSON parser parses and nothing it does not.

## What it brings

- **Evaluation-time errors.** Unknown fields, wrong types, missing required keys, invalid enum values, malformed statement tags — all fail during `nix eval`, before `nft` is ever invoked.
- **Complete coverage.** Every statement, expression, object type, family, hook, meta key, ct key, operator, and flag the 1.1.6 JSON parser accepts is exposed. No "happy path" subset; no quietly missing fields.
- **Composable.** Rules, chains, sets, maps, named objects, and commands are plain typed attrsets, composed and reused through ordinary Nix `let` bindings and function arguments.
- **Round-trip safe.** The same types that produce the JSON also describe what `nft -j list ruleset` emits, so reading existing state back into the same model is a possibility, not a rewrite.
- **Declarative DSL on top of the type layer.** Path-based field access, flat operators, variant namespaces, and `chains.<name>.rules = [...]` table trees. Produces the same validated attrsets as the raw type layer and can be mixed with hand-written commands in a single ruleset.
- **Auditable.** Every field and enum value is derived directly from the nftables C source, and the derivation is documented below. "1:1 with the spec" here means the implementation, not the man page.

## What it does

Given typed Nix input describing tables, chains, rules, sets, maps, named objects, and commands, the library:

1. Validates the structure at evaluation time using `types.submodule` and `types.attrTag` discriminated unions — every statement and expression is identified by a single key, which is exactly what `attrTag` dispatches on.
2. Renders the validated value to the exact JSON shape libnftables expects, stripping unset option defaults while preserving semantically-meaningful nulls (e.g. `{ accept = null; }`, `{ flush = { ruleset = null; }; }`).
3. Produces a string suitable for writing to a file and feeding to `nft -j -f`.

Coverage:

- Recursive `expression` type covering every form the JSON parser accepts (payloads, meta/ct/rt/fib/ipsec/tunnel, numgen/hash, set/map/concat/prefix/range, binary ops, verdicts, etc.).
- `statement` type for every rule building block (match, counter, nat, log, limit, meter, queue, last, flow, tproxy, synproxy, reset, secmark, tunnel, …).
- Ruleset object types — table, chain, rule, set, map, element, flowtable, counter, quota, ct helper, ct timeout, ct expectation, limit, secmark, synproxy, tunnel, metainfo — with discriminated unions for add/replace/create/insert/delete/destroy/list/reset/flush/rename commands.
- `toJSON` renderer that strips unset option defaults but preserves significant nulls.
- 240+ round-trip tests wired into `nix flake check`, plus a live-parser integration suite that pipes generated rulesets through `unshare -rn nft -c -j -f` to catch any divergence from what real nftables accepts.

## Usage

### DSL (recommended)

Path-based field access, top-level operators, variant namespaces, and a declarative table tree. Chains and named objects live under `chains.<name>` / `sets.<name>` / `maps.<name>`; rules are lists of statements.

```nix
{
  inputs.nix-nft-types.url = "path:./nix-nft-types";

  outputs = { self, nixpkgs, nix-nft-types }: {
    packages.x86_64-linux.rules =
      let
        nftlib = nix-nft-types.lib;
        inherit (nftlib.dsl) ruleset flush table eq inSet accept counter limit;
        inherit (nftlib.dsl.fields) tcp ct;
      in
      nixpkgs.legacyPackages.x86_64-linux.writeText "rules.json" (nftlib.toJSON (ruleset [
        flush
        (table "inet" "filter" {
          chains.input = {
            type = "filter"; hook = "input"; prio = 0; policy = "drop";
            rules = [
              [ (inSet ct.state [ "established" "related" ]) accept ]
              [ (eq tcp.dport 22) (limit { rate = 10; per = "minute"; burst = 5; }) accept ]
            ];
          };
        })
      ]));
  };
}
```

Key entry points under `nftlib.dsl`:

| | |
|---|---|
| `fields.<proto>.<name>` | pre-built payload leaves (`fields.tcp.dport`, `fields.ip.saddr`, `fields.ct.state`, `fields.meta.iifname`, `fields.fib.oif`, …) |
| `payload` / `payloadRaw` / `payloadTunnel` | escape hatches for fields not in the tree |
| `eq` / `ne` / `lt` / `gt` / `le` / `ge` | match operators producing `{ match: { left; right; op; } }` |
| `inSet` / `notInSet` / `within` | set-membership match — auto-wraps a list rhs as `{ set = […]; }`, passes `"@name"` through |
| `match.in_` / `match.raw` | bitwise `in` operator + raw escape hatch |
| `accept` / `drop` / `continue` / `return` / `notrack` | verdicts as values |
| `jump target` / `goto target` | verdicts with targets |
| `counter` / `reject` / `log` / `limit` / `quota` / `synproxy` / `masquerade` / `redirect` / `queue` | callable attrsets with `.auto` / `.plain` / `.ref` variants (`counter {…}` vs `counter.auto` vs `counter.ref "name"`) |
| `snat` / `dnat` / `fwd` / `dup` / `tproxy` | NAT statements |
| `flow` / `meter` / `vmap` / `mangle` / `setStmt` / `mapStmt` / `last` / `lastUsed` / … | remaining statements |
| `expr.concat` / `expr.set` / `expr.map` / `expr.prefix` / `expr.range` / `expr.numgen` / `expr.jhash` / … | structural and generator expressions |
| `ruleset` / `table` | top-level builders |
| `flush` / `flushRuleset` / `flushTable` / `flushChain` / `flushSet` / `flushMap` | flush commands (bare `flush` = flush everything; siblings take an object body). nftables rejects `flush flowtable`, so that combination is intentionally absent. |
| `rule` | standalone `add rule` (for when a rule needs an explicit handle/index outside the table tree) |
| `create.<kind>` / `delete.<kind>` / `destroy.<kind>` / `list.<kind>` | per-object-kind command namespaces. `delete` / `destroy` / `list` cover all 16 add-object kinds (table, chain, rule, set, map, element, flowtable, counter, quota, ctHelper, limit, ctTimeout, ctExpectation, secmark, synproxy, tunnel). `list` additionally exposes `metainfo` (read-back shape from `nft -j list`). `create` covers the same 16 minus `rule` — nftables explicitly rejects `create rule`, so the DSL routes rule-adds through `rule` / the table-tree `rules = [...]` path. |
| `rename.chain` | rename a chain (chain-only per the schema) |
| `reset.<kind>` | reset a counter, quota, rule, set, map, or element; also callable as a statement (`reset tcpOption`) via `__functor` |
| `replace` / `insert` | rule-only commands (`replace` needs `handle`, `insert` optionally takes `index`) |

Camel-case attribute names are translated to hyphenated JSON keys where nftables expects them (`queueThreshold` → `queue-threshold`, `srcIpv4` → `src-ipv4`, `gcInterval` → `gc-interval`) — see `lib/dsl/internal/rename.nix`. Users never write hyphens.

Emission order inside a `dsl.table` expansion is deterministic: `add table` → `add chain` (alphabetical) → `add <object>` (alphabetical by kind, then name) → `add rule` (alphabetical by chain, source order within chain). Chains are emitted before objects so verdict-map elements (`{ jump = { target = "wan"; }; }`) resolve during the atomic transaction; rules come last so they can reference both chains and objects.

### Raw attrsets

The typed layer is directly usable if the DSL's conventions don't fit — every command is a plain attrset matching the JSON shape:

```nix
{
  nftables = [
    { flush = { ruleset = null; }; }
    { add = { table = { family = "inet"; name = "filter"; }; }; }
    { add = { rule = {
        family = "inet"; table = "filter"; chain = "input";
        expr = [
          { match = {
              left = { payload = { protocol = "tcp"; field = "dport"; }; };
              right = 22; op = "==";
          }; }
          { accept = null; }
        ];
    }; }; }
  ];
}
```

`nftlib.toJSON` on that value yields a byte-identical result to the DSL form. Raw commands and DSL children can appear side-by-side inside `dsl.ruleset [...]`.

### Running

At runtime: `nft -j -f rules.json`.

Examples:

- `examples/basic-firewall-dsl.nix` — minimal firewall in the DSL.
- `examples/home-router-dsl.nix` — realistic home-router: two tables, three set-flag combinations, named counters/limits, flowtable offload, verdict-map dispatch, concatenated-key port-forward map, rate-limited SSH, ICMP shaping.
- `examples/basic-firewall.nix` — the same minimal firewall in hand-written raw attrsets, kept as a reference for users who prefer to bypass the DSL.

## How this was built

The canonical "libnftables-json spec" is `doc/libnftables-json.adoc`, rendered as the `libnftables-json(5)` man page. The first pass built the types directly from that document: every JSON key, enum value, family, hook, meta-key, and operator became a Nix enum (`lib/primitives.nix`); each structural form became a `types.submodule` (`lib/expressions.nix`, `lib/statements.nix`, `lib/objects.nix`); tagged unions used `types.attrTag`. A `toJSON` renderer stripped `null` defaults while preserving semantically-meaningful nulls. The library passed its own test suite and matched the adoc.

Verifying output against `nft -c` surfaced failures the adoc did not predict. Walking the nftables C source revealed the adoc to be genuinely incomplete. Statements (`last`, `flow`, `tproxy`, `synproxy`, `reset`, `secmark`, `tunnel`), expressions (`ipsec`/xfrm, `tunnel` metadata, `ip option`), and named object types (`secmark`, `synproxy`, `tunnel`) were entirely absent from the documentation but fully supported by the parser. Other sections were actively wrong: `ct timeout` is documented with flat `state` + `value` fields but `parser_json.c:3550` reads a nested `policy` object mapping state names to timeout seconds; `ct timeout` and `ct expectation` are documented as accepting 8 protocols but the parser only branches on `tcp` and `udp`. Enum values (`netmap` NAT flag, `dynamic` set flag, `egress` hook, `arp`/`bridge`/`netdev` families), fields (`comment` on tables/chains/named objects, `stmt` on sets and set/map statements, `type_flags` on NAT, `size` on meters, `rate_unit`/`burst_unit` on limits, `ih` inner-header payload base, socket `mark`/`wildcard`, ~14 missing meta keys), and structural types (`chain.dev` accepts string or array-of-strings) were missing. Raw `tcp option` and tunneled `payload` forms exist in the parser and are not mentioned at all.

The source of truth was therefore pivoted from the adoc to `src/parser_json.c` (plus `src/meta.c`, `src/ct.c`, `src/xfrm.c`, `src/tunnel.c`, `src/rule.c`). Every `json_parse_*_stmt`, `json_parse_*_expr`, and each branch of `json_parse_cmd_add_object` was walked field-by-field: keys read via `json_unpack_err` (required) or `json_unpack` (optional) were listed with their format char (`s:s`/`s:i`/`s:I`/`s:b`/`s:o`) driving the Nix type; the Nix body was diffed against that list; every enum was cross-referenced with its parser lookup table to confirm exhaustiveness. The output side (`src/json.c`) was then audited for round-trip compatibility with `nft -j list` output — this caught one more gap (`{counter: null}` emitted in stateless mode, which the parser accepts but the Nix type had rejected).

### What "1:1 with the spec" means here

- **1:1 with `parser_json.c`** on the input side: every field the parser reads is exposed, with matching type and required/optional semantics.
- **Round-trip compatible with `json.c`** on the output side: every key and enum value `nft -j list` emits is readable by the input side.
- **Not 1:1 with the adoc.** The library is strictly broader than the adoc because the adoc is outdated and has documented errors. Claims of `libnftables-json` compliance are accurate only if compliance is defined against the implementation, not the documentation.

## Caveats

- The `tunnel` named object's nested `tunnel` field has type-dependent shape (VXLAN vs ERSPAN v1 vs ERSPAN v2 vs GENEVE). These are modeled as `types.oneOf` with `addCheck` discriminators — strict but not cross-validated against the sibling `type` field.
- An upstream bug (`parser_json.c:3913`) writes the `dport` JSON field into `obj->tunnel.sport`. The Nix types correctly expose both fields; the fix has to happen upstream.

## Layout

```
lib/
  primitives.nix          enums: family, hook, operator, meta-key, etc.
  expressions.nix         recursive `expression` type
  statements.nix          `statement` attrTag union
  objects.nix             tables/chains/rules/sets/named objects + union types
  commands.nix            add/replace/create/insert/delete/destroy/list/reset/flush/rename + ruleset envelope
  render.nix              toJSON with null-stripping
  default.nix             entry point
  dsl/                    DSL — declarative table tree + path-based field access
    default.nix             top-level entry aggregating every sub-module
    fields/                 pre-built payload and meta/ct/rt/socket/fib/ipsec/tunnelMeta leaves
    ops.nix                 eq / ne / lt / gt / le / ge / inSet / notInSet / within / match
    verdicts.nix            accept / drop / continue / return / notrack / jump / goto
    exprs.nix               concat / set / map / prefix / range / numgen / jhash / … and header-option escape hatches
    payload.nix             payload / payloadRaw / payloadTunnel escape hatches
    actions/                counter, reject, log, rate, nat, synproxy, queue, ct, flow, misc — one file per statement group
    structure/              ruleset envelope, declarative `table` node, renderer that expands the tree into commands
    internal/               compact, rename, variant (__functor helper), markers
tests/
  default.nix             schema tests for the raw type layer
  dsl-parity.nix          parity tests for the DSL + renderer tests + error-case tests
  dsl-integration.nix     live-parser tests: each ruleset is piped through `unshare -rn nft -c -j -f`
examples/
  basic-firewall.nix      hand-written raw attrsets (reference for users bypassing the DSL)
  basic-firewall-dsl.nix  same firewall via the DSL
  home-router-dsl.nix     comprehensive DSL showcase
```

## Running the tests

```
nix flake check
```

Runs 240+ Nix-level tests (schema validation of hand-written raw attrsets, DSL↔raw byte-for-byte parity, renderer tests for emission order and error cases, and schema validation of each example) plus 10 integration tests that pipe each example and each command-kind combo through a real `nft -c -j -f` inside a private network namespace.

Rendering an example ruleset to JSON for inspection:

```
nix eval --impure --raw --expr '
  let
    flake = builtins.getFlake (toString ./.);
    example = import ./examples/home-router-dsl.nix { nftlib = flake.lib; };
  in flake.lib.toJSON example
' | jq
```

Manually validating the output against the live nftables parser (requires `nftables` and an unprivileged user namespace):

```
nix eval --impure --raw --expr '
  let flake = builtins.getFlake (toString ./.); in
  flake.lib.toJSON (import ./examples/home-router-dsl.nix { nftlib = flake.lib; })
' > /tmp/rules.json
unshare -rn nft -c -j -f /tmp/rules.json
```
