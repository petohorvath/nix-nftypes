# nix-nft-types

Typed Nix bindings for nftables. Rulesets are built as structured Nix values, type-checked at evaluation time, then rendered either to libnftables-JSON for `nft -j -f` or to nftables text syntax for `nft -f`.

Authoritative reference: **nftables post-1.1.6 development** (upstream commit `f7dc8269ddaed49fe643423a3a403b91ab1e50db`, `v1.1.6-105-gf7dc8269`, 2026-04-22). Every field, enum, and structural decision in this library is derived from that revision; the released `v1.1.6` tag is 2025-12-03 and predates several schema-relevant parser changes the audit covers.

Related docs:

- [`docs/spec-coverage.md`](docs/spec-coverage.md) — file-by-file audit of `lib/schema/` against `parser_json.c`. Coverage matrix, enum verification, every adoc-vs-parser deviation the schema captures, edge cases where schema and parser deliberately diverge.
- [`docs/dsl-coverage.md`](docs/dsl-coverage.md) — DSL audit against the schema. Confirms every shape the schema accepts is reachable from `lib/dsl/`, either via pre-built constructors or escape hatches.
- [`docs/text-coverage.md`](docs/text-coverage.md) — text renderer (`lib/text/`) coverage notes and known limitations.

## Why this exists

Writing nftables rulesets is error-prone. The classic `nft` syntax is stringy, has no static checking, and typos only surface when the ruleset hits the kernel. Generating that syntax from Nix makes things worse — string concatenation, shell-escaping footguns, no structural composition beyond `lib.concatStringsSep`. The `nft -j` JSON interface is more robust, but hand-writing that JSON is miserable, and the `libnftables-json(5)` man page that should describe what is legal is incomplete and in places actively wrong. Existing Nix firewall libraries either rebuild `nft` syntax with ad-hoc types, or type a thin slice of the JSON schema based on the man page — which is not what `nft -j -f` actually accepts.

This library closes that gap: a full, strict, source-of-truth type system for nftables rulesets in Nix, covering everything the JSON parser parses and nothing it does not.

## What it brings

- **Evaluation-time errors.** Unknown fields, wrong types, missing required keys, invalid enum values, malformed statement tags — all fail during `nix eval`, before `nft` is ever invoked. The DSL routes every user-supplied object body through the matching schema submodule; a type-mismatched field throws at eval time with the user's tree path named (e.g. `chains.c.prio: not of type 'null or signed integer'`), instead of silently rendering to JSON where `nft -j -f` would drop the broken section.
- **Complete coverage.** Every statement, expression, object type, family, hook, meta key, ct key, operator, and flag the audited JSON parser accepts is exposed. No "happy path" subset; no quietly missing fields.
- **Composable.** Rules, chains, sets, maps, named objects, and commands are plain typed attrsets, composed and reused through ordinary Nix `let` bindings and function arguments.
- **Round-trip safe.** The same types that produce the JSON also describe what `nft -j list ruleset` emits, so reading existing state back into the same model is a possibility, not a rewrite.
- **Two renderers, one schema.** The validated attrsets render either to libnftables-JSON (`toJson`/`toNix`) or to nftables text syntax (`toText`/`toTextPretty` for full rulesets, `toTextBlock`/`toTextBlockPretty` for the contents of one table block). A `render-equivalence` test suite loads JSON and text into separate netns and diffs `nft list ruleset` output to enforce the 1:1 contract.
- **Declarative DSL on top of the nft-types layer.** Path-based field access, flat operators, variant namespaces, and `chains.<name>.rules = [...]` table trees. Produces the same validated attrsets as the nft-types layer and can be mixed with hand-written commands in a single ruleset.
- **Auditable.** Every field and enum value is derived directly from the nftables C source, and the derivation is documented below. "1:1 with the spec" here means the implementation, not the man page.

## What it does

Given typed Nix input describing tables, chains, rules, sets, maps, named objects, and commands, the library:

1. Validates the structure at evaluation time using `types.submodule` and `types.attrTag` discriminated unions — every statement and expression is identified by a single key, which is exactly what `attrTag` dispatches on.
2. Renders the validated value either to the exact JSON shape libnftables expects (stripping unset option defaults while preserving semantically-meaningful nulls — e.g. `{ accept = null; }`, `{ flush = { ruleset = null; }; }`), or to the equivalent nftables text syntax.
3. Produces a string suitable for writing to a file and feeding to `nft -j -f` (JSON) or `nft -f` (text).

Coverage:

- Recursive `expression` type covering every form the JSON parser accepts (payloads, meta/ct/rt/fib/ipsec/tunnel, numgen/hash, set/map/concat/prefix/range, binary ops, verdicts, etc.).
- `statement` type for every rule building block (match, counter, nat, log, limit, meter, queue, last, flow, tproxy, synproxy, reset, secmark, tunnel, …).
- Ruleset object types — table, chain, rule, set, map, element, flowtable, counter, quota, ct helper, ct timeout, ct expectation, limit, secmark, synproxy, tunnel, metainfo — with discriminated unions for add/replace/create/insert/delete/destroy/list/reset/flush/rename commands.
- `toJson` / `toNix` renderer that strips unset option defaults but preserves significant nulls.
- `toText` / `toTextPretty` renderer that emits the equivalent nftables text syntax (`.nft`) — pure Nix, mirrors the JSON renderer's position in the pipeline, no shell-out to `nft`.
- `toTextBlock` / `toTextBlockPretty` render the contents of one `table { ... }` block (no wrapper, no `add` keyword, rules folded as inline statements inside their parent chain) — for embedding in host modules that supply their own wrapper, like nixpkgs' `networking.nftables.tables.<n>.content`.
- 240+ Nix-level tests (schema, DSL parity, renderer, error cases) wired into `nix flake check`, plus three live-parser suites: one pipes JSON through `unshare -rn nft -c -j -f`, one pipes text through `unshare -rn nft -c -f -`, and one loads each case via both renderers into separate netns and diffs `nft list ruleset` to enforce JSON↔text equivalence. Two further suites exercise the DSL's schema validation: one asserts each constructor throws on a clearly-invalid field (`tests/dsl-validation.nix`), one asserts the thrown message names the offending path (`tests/dsl-validation-messages.nix`).

## Two layers

Two input layers that both produce the validated attrsets either renderer consumes:

1. **nft-types layer** (`lib/`) — `types.submodule` + `types.attrTag` modules that mirror the shapes `parser_json.c` accepts. Input is plain typed attrsets matching the libnftables JSON shape, e.g. `{ add = { rule = { family = "inet"; chain = "input"; expr = [ … ]; }; }; }`. This is the layer the project is named after.
2. **DSL** (`lib/dsl/`) — a declarative tree on top of the nft-types layer: path-based field access (`tcp.dport`, `ct.state`), flat operators (`eq`, `inSet`), variant namespaces (`counter.auto`, `reject.tcp-reset`), and a `chains.<name>.rules = [ … ]` table tree. Every DSL value reduces to a validated nft-types attrset — nothing bypasses the schema.

Both layers are reachable under `nftlib`; raw nft-types commands and DSL children can appear side-by-side in a single `ruleset`.

## Two renderers

The same validated attrset can be rendered two ways:

| | output | consumed by |
|---|---|---|
| `nftlib.toJson` / `toNix` | `libnftables-json` (compact / pretty) | `nft -j -f` |
| `nftlib.toText` / `toTextPretty` | nftables text syntax, full ruleset (compact / multi-line) | `nft -f` |
| `nftlib.toTextBlock` / `toTextBlockPretty` | block-form contents of one table (compact / multi-line) | inside a host-supplied `table <fam> <name> { ... }` wrapper |

All three consume the cleaned attrset directly — none shells out to `nft`. The text paths mirror the JSON path's position in the pipeline; nothing in the schema or DSL has to know which renderer will run. The `render-equivalence-tests` suite (in `tests/render-equivalence.nix`) loads each test case via both full-ruleset renderers into separate network namespaces and diffs `nft list ruleset` to enforce that they produce the same loaded ruleset.

`toTextBlock` accepts a single `dsl.table` value and emits only the inside of that table block — no `table <fam> <name> { ... }` wrapper, no `add` keyword on object decls, rules folded as inline statements inside their parent chain. The intended consumer is a host module that already manages the wrapper (e.g. nixpkgs' `networking.nftables.tables.<n>.content`).

A handful of inputs are accepted by the JSON parser but not the text grammar (e.g. a flowtable named `offload`, since the text parser treats `offload` as a reserved word in flowtable position). Those cases are listed in `tests/text-integration.nix::knownTextLimitations`; the JSON path remains the authoritative target for them.

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
      nixpkgs.legacyPackages.x86_64-linux.writeText "rules.json" (nftlib.toJson (ruleset [
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
| `flush` / `flushRuleset` / `flushTable` / `flushChain` / `flushSet` / `flushMap` / `flushMeter` | flush commands (bare `flush` = flush everything; siblings take an object body). nftables rejects `flush flowtable`, so that combination is intentionally absent. |
| `rule` | standalone `add rule` (for when a rule needs an explicit handle/index outside the table tree) |
| `create.<kind>` / `delete.<kind>` / `destroy.<kind>` / `list.<kind>` | per-object-kind command namespaces. `delete` / `destroy` / `list` cover all 16 add-object kinds (table, chain, rule, set, map, element, flowtable, counter, quota, ctHelper, limit, ctTimeout, ctExpectation, secmark, synproxy, tunnel). `list` additionally exposes `metainfo` (read-back shape from `nft -j list`) and `meter` (anonymous-set-backed meters). `create` covers the same 16 minus `rule` — nftables explicitly rejects `create rule`, so the DSL routes rule-adds through `rule` / the table-tree `rules = [...]` path. |
| `rename.chain` | rename a chain (chain-only per the schema) |
| `reset.<kind>` | reset a counter, quota, rule, set, map, or element; also callable as a statement (`reset tcpOption`) via `__functor` |
| `replace` / `insert` | rule-only commands (`replace` needs `handle`, `insert` optionally takes `index`) |

Camel-case attribute names are translated to hyphenated JSON keys where nftables expects them (`queueThreshold` → `queue-threshold`, `srcIpv4` → `src-ipv4`, `gcInterval` → `gc-interval`) — see `lib/dsl/internal/rename.nix`. Users never write hyphens.

Emission order inside a `dsl.table` expansion is deterministic: `add table` → `add chain` (alphabetical) → `add <object>` (alphabetical by kind, then name) → `add rule` (alphabetical by chain, source order within chain). Chains are emitted before objects so verdict-map elements (`{ jump = { target = "wan"; }; }`) resolve during the atomic transaction; rules come last so they can reference both chains and objects.

### Raw attrsets

The nft-types layer is directly usable if the DSL's conventions don't fit — every command is a plain attrset matching the JSON shape:

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

`nftlib.toJson` on that value yields a byte-identical result to the DSL form. Raw commands and DSL children can appear side-by-side inside `dsl.ruleset [...]`.

### Static reference data

Three top-level exports surface kernel/man reference data downstream consumers (zone libraries, validators, doc generators) would otherwise rederive from `parser_json.c` or kernel headers.

- `nftlib.enums` — flat value lists for every primitive enum, sourced from the same binding the `types.enum` definitions read. Drop-in replacement for `types.<x>.functor.payload.values`.

  ```nix
  nftlib.enums.family   # → [ "ip" "ip6" "inet" "arp" "bridge" "netdev" ]
  ```

- `nftlib.compatibility` — `man nft` Tables 6 and 7 plus the kernel's `oifname`-availability rule, transcribed: `hooksByFamily`, `familiesByChainType`, `priorityIntsDefault`, `priorityIntsBridge`, `hooksWithOifname`.

  ```nix
  nftlib.compatibility.hooksByFamily.netdev   # → [ "ingress" "egress" ]
  ```

- `nftlib.resolvePriority` — symbolic chain priority → int, with family-aware lookup. Bridge family uses `priorityIntsBridge`; every other known family uses `priorityIntsDefault`. Ints pass through unchanged. Unknown family or unknown symbol throws (with distinct messages).

  ```nix
  nftlib.resolvePriority "bridge" "filter"   # → -200
  nftlib.resolvePriority "ip" "filter"       # → 0
  nftlib.resolvePriority "ip" 42             # → 42
  ```

### Running

At runtime: `nft -j -f rules.json` (JSON) or `nft -f rules.nft` (text). Both rendering paths produce equivalent loaded rulesets — pick whichever fits the consumer.

Examples:

- `examples/basic-firewall-dsl.nix` — minimal firewall in the DSL.
- `examples/home-router-dsl.nix` — realistic home-router: two tables, three set-flag combinations, named counters/limits, flowtable offload, verdict-map dispatch, concatenated-key port-forward map, rate-limited SSH, ICMP shaping.
- `examples/basic-firewall.nix` — the same minimal firewall in hand-written raw attrsets, kept as a reference for users who prefer to bypass the DSL.

## How this was built

The library was first written against the `libnftables-json(5)` adoc, then re-derived against `src/parser_json.c` after `nft -c` validation surfaced gaps the adoc didn't predict. The parser is the source of truth for both sides: every field it reads on input is exposed; every key and enum `nft -j list ruleset` emits on output is accepted on the input side. See [`docs/spec-coverage.md`](docs/spec-coverage.md) for the file-by-file audit (every adoc-vs-parser deviation the schema captures and every edge case where it deliberately diverges).

## Layout

```
lib/
  default.nix             entry point, wires schema → renderers + DSL
  clean.nix               shared null-stripping recursion (used by both renderers)
  compatibility.nix       man nft Tables 6/7 reference data + resolvePriority helper
  schema/                 type-checked libnftables-json schema
    internal.nix            private helpers (discriminatedSubmodule, listOfLen, tagOpt, wrap)
    primitives.nix          enums: family, hook, operator, meta-key, etc.
    expressions.nix         recursive `expression` type
    statements.nix          `statement` attrTag union
    objects.nix             tables/chains/rules/sets/named objects + union types
    commands.nix            add/replace/create/insert/delete/destroy/list/reset/flush/rename + ruleset envelope
  json/                   toJson / toNix (null-stripping via clean)
    default.nix             entry point
  text/                   toText / toTextPretty (full rulesets) + toTextBlock / toTextBlockPretty (single-table block form)
    context.nix             pretty/compact mode, indent depth, parent-precedence threading
    primitives.nix          identifier quoting, string escape, flag joining
    expressions.nix         all expression variants + binop precedence
    statements.nix          all statement variants
    objects.nix             ~16 object kinds, base/regular chain split, per-kind body grammar
    commands.nix            10 verbs + positional `create` for stateful objects
    default.nix             entry: clean → render commands → join with newlines
  dsl/                    DSL — declarative table tree + path-based field access
    default.nix             top-level entry aggregating every sub-module
    fields/                 pre-built payload and meta/ct/rt/socket/fib/ipsec/osf/tunnelMeta leaves
    ops.nix                 eq / ne / lt / gt / le / ge / inSet / notInSet / within / match
    verdicts.nix            accept / drop / continue / return / notrack / jump / goto
    exprs.nix               concat / set / map / prefix / range / numgen / jhash / … and header-option escape hatches
    payload.nix             payload / payloadRaw / payloadTunnel escape hatches
    actions/                counter, reject, log, rate, nat, synproxy, queue, ct, flow, misc — one file per statement group
    structure/              ruleset envelope, declarative `table` node, renderer that expands the tree into commands
    internal/               compact, rename, variant (__functor helper), markers, validate (DSL → schema submodule wiring)
tests/
  default.nix                  schema tests for the nft-types layer
  dsl-parity.nix               parity tests for the DSL + renderer tests + error-case tests
  dsl-integration.nix          live-parser tests: each ruleset is piped through `unshare -rn nft -c -j -f`
  dsl-validation.nix           per-submodule regression tests proving DSL constructors throw on type-mismatched bodies
  dsl-validation-messages.nix  end-to-end check that thrown error messages name the offending option path
  text-parity.nix              schema-level expected-string assertions for the text renderer
  text-integration.nix         live-parser tests for text: pipes each case through `unshare -rn nft -c -f -`
  text-block-parity.nix        expected-string + live-parser tests for toTextBlock / toTextBlockPretty
  render-equivalence.nix       loads JSON and text into separate netns, diffs `nft list ruleset`
examples/
  basic-firewall.nix      hand-written raw attrsets (reference for users bypassing the DSL)
  basic-firewall-dsl.nix  same firewall via the DSL
  home-router-dsl.nix     comprehensive DSL showcase
docs/
  spec-coverage.md        file-by-file audit of lib/schema/ vs parser_json.c
  dsl-coverage.md         DSL coverage audit against the schema layer
  text-coverage.md        text renderer coverage notes and known limitations
```

## Running the tests

```
nix flake check
```

Runs the full check matrix:

- **schema-tests** — 240+ Nix-level assertions: schema validation of hand-written raw attrsets, DSL↔raw byte-for-byte parity, renderer tests for emission order and error cases, and schema validation of each example.
- **integration-tests** — pipes each case's JSON through `unshare -rn nft -c -j -f` (real libnftables parser inside a private netns).
- **text-parity-tests** — schema-level expected-string assertions for `toText`.
- **text-integration-tests** — same case set as `integration-tests`, but rendered to text and piped through `unshare -rn nft -c -f -`.
- **text-block-parity-tests** — expected-string assertions for `toTextBlock` / `toTextBlockPretty`.
- **text-block-integration-tests** — wraps each block-form output in `table <fam> <name> { ... }` and pipes through `unshare -rn nft -c -f -`.
- **render-equivalence-tests** — for each case, loads JSON and text into separate netns and diffs `nft list ruleset`. The 1:1 contract.
- **dsl-validation-tests** — per-submodule regression coverage: every DSL constructor that takes a user body is exercised with an invalid field and required to `throw` at evaluation time.
- **dsl-validation-message-tests** — runs `nix-instantiate --eval` against representative bad expressions and asserts the stderr names the offending option path.

Rendering an example ruleset for inspection:

```
# JSON
nix eval --impure --raw --expr '
  let
    flake = builtins.getFlake (toString ./.);
    example = import ./examples/home-router-dsl.nix { nftlib = flake.lib; };
  in flake.lib.toJson example
' | jq

# Text (multi-line `.nft`)
nix eval --impure --raw --expr '
  let
    flake = builtins.getFlake (toString ./.);
    example = import ./examples/home-router-dsl.nix { nftlib = flake.lib; };
  in flake.lib.toTextPretty example
'
```

Manually validating the output against the live nftables parser (requires `nftables` and an unprivileged user namespace):

```
# JSON path
nix eval --impure --raw --expr '
  let flake = builtins.getFlake (toString ./.); in
  flake.lib.toJson (import ./examples/basic-firewall-dsl.nix { nftlib = flake.lib; })
' > /tmp/rules.json
unshare -rn nft -c -j -f /tmp/rules.json

# Text path
nix eval --impure --raw --expr '
  let flake = builtins.getFlake (toString ./.); in
  flake.lib.toTextPretty (import ./examples/basic-firewall-dsl.nix { nftlib = flake.lib; })
' > /tmp/rules.nft
unshare -rn nft -c -f /tmp/rules.nft
```
