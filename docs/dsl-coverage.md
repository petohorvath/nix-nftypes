# DSL coverage audit — `lib/dsl/` vs `lib/schema/`

This doc is the DSL counterpart of [`docs/spec-coverage.md`](spec-coverage.md).
Where that one verifies the schema layer is 1:1 with `parser_json.c`, this one
verifies the DSL layer is 1:1 with the schema. The README's claim is that
"every DSL value reduces to a validated nft-types attrset — nothing bypasses
the schema", and that the DSL exposes "every shape the schema accepts" via
either pre-built constructors or escape hatches.

## Coverage summary

| Surface | Schema bodies / tags | DSL constructors | Gaps fixed in this work |
|---|---|---|---|
| **Statement tags** | 31 (`statement` attrTag) | 40+ across `actions/` + `verdicts.nix` + `ops.nix` | 0 — full coverage already |
| **Expression tags** | 30 (`taggedExpression`) | 18 in `exprs.nix` + 180+ field leaves under `fields/` + 11 escape hatches | 2 field leaves (rt `ipsec`, fib `check`) + new `fields/osf.nix` for symmetry |
| **Add-object kinds** | 16 | 16 (`create.<kind>`, `delete.<kind>`, `destroy.<kind>`, `list.<kind>`, plus the declarative `table` tree) | 0 — full coverage |
| **Flush-object kinds** | 6 (table/chain/set/map/meter/ruleset) | 6 (`flush`, `flushTable`, `flushChain`, `flushSet`, `flushMap`, `flushMeter`) | 1 — added `flushMeter` |
| **List-object kinds** | 17 (16 add-objects + metainfo + meter) | 17 (`list.<kind>`, `list.metainfo`, `list.meter`) | 1 — added `list.meter` |
| **Reset-object kinds** | 6 | 6 | 0 |
| **Commands** | 10 verbs | 10 (every verb has a top-level constructor) | 0 |

**DSL gaps fixed**: 5 (4 DSL convenience leaves/builders + 1 schema gap that
this audit surfaced — `meter` was missing from `listObject`).

**Schema gap surfaced by this audit**: 1 — `listObject` didn't include
`meter` even though `parser_json.c:4191` accepts `list meter`. Fixed alongside
the DSL changes; logged here so a future schema audit is consistent.

## Methodology

For every schema body and every parser-accepted form, check whether the DSL
exposes a path that produces it. Two kinds of DSL surface count as coverage:

1. **Pre-built constructor** — convenience builder that takes idiomatic
   camelCase args and emits the right schema attrset (e.g.
   `dsl.fields.tcp.dport`, `dsl.counter.auto`, `dsl.create.table {…}`).
2. **Escape hatch** — generic builder that accepts any string / nested
   attrset and wraps it (e.g. `dsl.expr.rt {key = "ipsec"; family = "ip";}`,
   `dsl.payloadRaw {…}`, `dsl.match.raw {…}`). Escape hatches are the
   designed-in fallback for inputs the pre-built tree doesn't cover.

A DSL surface is **complete** for a schema body if either path can produce
every shape the schema accepts. A surface is a **gap** only if both paths
fail — i.e. the user has no idiomatic DSL way to produce some valid schema
shape and falls back to writing the raw attrset.

## Confirmed gaps (fixed in this work)

### D1. `fields/rt.nix` missing `ipsec` leaf

- **Schema**: `rtKeyType = enum [ "classid" "nexthop" "mtu" "ipsec" ]` after
  the spec-coverage G1 fix.
- **DSL pre-built**: `fields/rt.nix` only exposed `classid`, `nexthop`, `mtu`.
- **Escape hatch**: `dsl.expr.rt {key = "ipsec"; family = "ip";}` already
  worked.
- **Fix**: add `"ipsec"` to the keys list in `fields/rt.nix`. Now
  `dsl.fields.rt.ipsec == { rt = { key = "ipsec"; }; }`.

### D2. `fields/fib.nix` missing `check` leaf

- **Schema**: `fibResultType = enum [ "oif" "oifname" "type" "check" ]` after
  the spec-coverage G3 fix.
- **DSL pre-built**: `fields/fib.nix` only exposed `oif`, `oifname`, `type`.
- **Escape hatch**: `dsl.expr.fib {result = "check"; flags = [...];}` already
  worked.
- **Fix**: add `"check"` to the results list in `fields/fib.nix`.
  `parser_json.c:1213-1230` enforces flag combinations
  (saddr⊕daddr exactly one, iif⊕oif mutually exclusive), so a bare
  `dsl.fields.fib.check` is rejected by `nft -c` for everything but
  flag-using callers — the leaf is mostly useful in combination with the
  escape hatch's `flags`. Documented in the field file.

### D3. No `flushMeter` builder

- **Schema**: `flushObject` accepts `meter` after the spec-coverage G5 fix
  (`parser_json.c:4302`).
- **DSL pre-built**: `flush*` builders covered table/chain/set/map/ruleset
  only.
- **Fix**: add `flushMeter = body: { flush = { meter = body; }; };` to
  `lib/dsl/structure/ruleset.nix`. Now `dsl.flushMeter {family;table;name;}`
  works.

### D4. No `list.meter` builder

- **Schema gap surfaced**: `parser_json.c:4191` (`json_parse_cmd_list`
  dispatch) accepts `{"meter", CMD_OBJ_METER, json_parse_cmd_add_set}`. The
  schema's `listObject` didn't include `meter`, so even
  `{list = {meter = …};}` failed at evaluation time.
- **Fix (schema)**: add `meter = bodies.meterObjectBody;` to the
  `listObject` `attrTag`. Logged in spec-coverage as a follow-up gap S1.
- **Fix (DSL)**: add `meter = { tag = "meter"; body = lib.id; };` to
  `listObjectKinds` in `lib/dsl/structure/commands.nix`.
  `dsl.list.meter {family;table;name;}` works.

### D5. Stale comment in `structure/ruleset.nix`

- **Was**: comment said the schema accepts `flush flowtable` even though
  the parser rejects it, justifying the DSL omission.
- **Now**: schema rejects it too (after spec-coverage G4). Comment
  updated to reflect that schema and DSL agree on omission.

### D6. No `fields/osf.nix` (small consistency improvement)

- **Schema**: `osfKeyType = enum [ "name" "version" ]` after the
  spec-coverage G2 fix.
- **DSL pre-built**: no `osf` namespace under `fields/`.
- **Escape hatch**: `dsl.expr.osf {key = "version"; ttl = "loose";}` works.
- **Fix**: add a tiny `lib/dsl/fields/osf.nix` exposing both keys, mirroring
  the rt/fib/socket pattern. Keeps the field tree symmetric.

## Inverse audit — DSL → schema

For every DSL constructor, verify the produced attrset is accepted by the
schema. Walked module-by-module:

- `actions/counter.nix`: emits `{counter = null}`, `{counter = "name"}`, or
  `{counter = {packets?; bytes?;}}`. Schema's `counterRefOrBody = oneOf
  [nullType str submodule{packets,bytes}]` accepts all three. ✓
- `actions/rate.nix` (limit, quota): emits ref-or-inline forms matching
  `limitRefOrBody` / `quotaRefOrBody`. Crucially, **does not emit the
  vestigial `unit` field** that the schema removed in spec-coverage F6.
  Verified by `grep '\bunit\b' lib/dsl/`. ✓
- `actions/log.nix`: applies `rename.log` (`queueThreshold` →
  `queue-threshold`) before emission. ✓
- `actions/synproxy.nix`: anonymous form requires both `mss` and `wscale`,
  matching the schema's `synproxyAnonBody`. (Spec-coverage E10 notes the
  schema is stricter than the parser here; the DSL inherits that posture.)
- `actions/nat.nix`, `actions/queue.nix`, `actions/reject.nix`,
  `actions/ct.nix`, `actions/flow.nix`, `actions/misc.nix`: each constructor
  emits the exact body shape the corresponding schema body accepts.
- `actions/flow.nix`: `flow {flowtable;}` defaults `op = "add"` — matches
  the schema's `flowOpType = ["add"]` (parser only accepts "add").
- `verdicts.nix`: emits `{accept = null;}` etc. and `{jump = {target = …;};}`
  matching the schema's verdict tags. ✓
- `ops.nix`: every operator emits `{match = {left; right; op;};}` with `op`
  drawn from the schema's `operatorType` enum. ✓
- `exprs.nix`: every constructor emits a tag listed in
  `expressions.nix:taggedExpression`. ✓
- `fields/*.nix`: every leaf is `{TAG = {key|result|… = "...";};}` shaped
  for its schema body.
- `structure/render.nix`: object-tree expansion emits per-kind `{add =
  {<TAG> = body;};}` with the right rename map applied. ✓
- `structure/commands.nix`: per-verb namespace `{<verb> = {<TAG> = body;};}`,
  with rename for `set`/`map`/`element`/`tunnel` bodies. ✓

No DSL constructor was found to emit a shape the schema rejects.

## Edge cases and design choices

### E1. The `dsl.reset` `__functor` overload

`reset` does double-duty as a rule-body **statement** (`reset tcpOption`)
and a top-level **command** namespace (`reset.counter {…}`). Implemented
via `internal/variant.nix`'s `__functor` helper: bare call → statement,
sub-attribute access → command builder. This is the only place a single
DSL name covers both a statement and a command.

### E2. Binary operators are pairwise in the DSL but variadic in the schema

`dsl.expr.bitor a b == { "|" = [a b]; }` — only handles two operands. The
schema accepts `≥2` (`binaryOpBody = listOfMinLen 2`). For chained ops,
users nest: `bitor a (bitor b c)`. Most realistic uses are pairwise; the
nested form covers the rare longer chain. Not a gap, just a stylistic
choice.

### E3. Field leaves don't include conditional refinements

`dsl.fields.rt.nexthop` → `{rt = {key = "nexthop";}}` — no `family`. The
parser uses `family` to pick `NEXTHOP4` vs `NEXTHOP6` (rt is the only key
where this matters). Users who need it write the escape hatch:
`dsl.expr.rt {key = "nexthop"; family = "ip6";}`. Same pattern for
`fields.ct.<key>` (no `dir`/`family` refinement) and `fields.fib.<result>`
(no `flags`). The pre-built leaves are deliberately the bare minimum;
refinements live in the escape hatches.

### E4. `setStmt` / `mapStmt` rename to avoid collision

`set` and `map` already exist as DSL expression constructors
(`exprs.set xs == {set = xs;}` and `exprs.map {key; data;}`). The
rule-body statements that modify a set/map (`{set = {op; elem; set;};}`
and `{map = {op; elem; data; map;};}`) couldn't reuse the names without
shadowing — so `actions/misc.nix` exposes them as `setStmt` and `mapStmt`.
The DSL spelling is intentional; the resulting JSON shape is unchanged.

### E5. `xt` statement is exposed in the DSL but rejected by the parser

The DSL exposes `dsl.xt type name → {xt = {type; name;};}` for round-trip
with `nft -j list ruleset` output. The parser rejects xt as input
(`parser_json.c:2942-2944`); see spec-coverage E2. No-op for input use.

### E6. Plural list/reset object kinds (`tables`, `chains`, …) not exposed

Per spec-coverage E11, the schema doesn't model the plural list-multiple
forms (read-back-only shapes from `nft -j list ruleset`). The DSL inherits
that omission — `list.tables` is intentionally absent. If round-trip parsing
of plural-list output is needed in the future, both layers extend together.

### E7. Renames concentrated in `internal/rename.nix`

The DSL hides hyphenated JSON keys (`queue-threshold`, `gc-interval`,
`auto-merge`, `src-ipv4`, …) behind camelCase user-facing names. All
renames live in `lib/dsl/internal/rename.nix` (14 explicit mappings) plus
the `elements` → `elem` plural-for-lists DSL convention. Users never write
hyphenated keys.

## Out of scope for this audit

- Text renderer coverage: see [`docs/text-coverage.md`](text-coverage.md).
- Schema-vs-parser audit: see [`docs/spec-coverage.md`](spec-coverage.md).
- Schema-layer code quality: see [`docs/code-review.md`](code-review.md).
- DSL-internal refactorings (e.g. unifying the variant pattern, splitting
  large action modules): not a coverage concern, deferred.

## Verification

`nix flake check` passes the full matrix:

- `schema-tests` — 240+ assertions including 5 spec-coverage gap-fix tests
  + 7 new DSL parity tests (rt ipsec, fib check, osf name, osf version,
  flushMeter, list.meter, plus the existing rt/fib leaves).
- `text-parity-tests`, `integration-tests`, `text-integration-tests`,
  `render-equivalence-tests` — all unchanged by the DSL additions.
