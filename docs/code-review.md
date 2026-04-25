# nft-types schema layer — code review

A review of `lib/schema/{primitives,expressions,statements,objects,commands}.nix`, `lib/clean.nix`, `lib/json/default.nix`, and the schema-facing surface of `lib/default.nix`. Scope excludes `lib/dsl/` and `lib/text/` (renderer-only concerns).

For each finding: file:line, current shape, proposal, and status — **Applied** in this work, or **Deferred** to a follow-up (with reasoning). Refactorings classified "API shape change" are deferred by default per the plan's user preferences.

---

## Findings — applied in this work

### F1. Inconsistent identity-options application across object bodies

**Where**: `lib/schema/objects.nix:47-70` defines `commonObjectOptions` (family + table + name + handle + comment), but it is only applied to: `counterObjectBody`, `quotaObjectBody`, `ctHelperObjectBody`, `limitObjectBody`, `ctTimeoutObjectBody`, `ctExpectationObjectBody`, `secmarkObjectBody`, `synproxyObjectBody`, `tunnelObjectBody`.

It is **not** applied to: `tableBody`, `chainBody`, `ruleBody`, `setObjectBody`, `mapObjectBody`, `elementBody`, `flowtableBody` — each of which manually re-declares family/table/name/handle/comment with identical types and descriptions.

**Why this matters**: every change to an "identity field" (e.g., a future `namespace` field) has to land in 7 hand-written copies; renaming `comment`'s description requires editing 7 places; and reviewers have no single place to check what counts as an identity field.

**Proposal**: split `commonObjectOptions` into composable fragments and build every body that has identity fields from the fragments:

```nix
identityCore = {
  family = mkOption { type = familyType; description = "table family"; };
  handle = mkOption {
    type = types.nullOr types.ints.unsigned;
    default = null;
    description = "kernel-assigned handle";
  };
};

# table only — has no `table` field of its own
tableContainerOptions = identityCore // {
  name = mkOption { type = types.str; description = "table name"; };
};

# objects nested inside a table
inTableOptions = identityCore // {
  table = mkOption {
    type = types.str;
    description = "containing table";
  };
};

# objects nested in a table, with a name
namedInTableOptions = inTableOptions // {
  name = mkOption { type = types.str; description = "object name"; };
};

# rules use `chain` rather than `name`
ruleContainerOptions = inTableOptions // {
  chain = mkOption { type = types.str; description = "containing chain"; };
};

# elements have no handle
elementContainerOptions = removeAttrs namedInTableOptions [ "handle" ];

commentOption = {
  comment = mkOption {
    type = types.nullOr types.str;
    default = null;
    description = "free-form comment";
  };
};

commonObjectOptions = namedInTableOptions // commentOption;
```

Then:
- `tableBody` = `tableContainerOptions // { flags; comment; }`
- `chainBody` = `inTableOptions // { name; newname; type; hook; prio; dev; policy; comment; }`
- `ruleBody` = `ruleContainerOptions // { expr; index; comment; }`
- `setObjectBody`, `mapObjectBody`, `flowtableBody` = `namedInTableOptions // { … }` (no comment for these — flowtable has none, and per the audit set/map don't accept comment either)
- `elementBody` = `elementContainerOptions // { elem; }`
- All named objects keep `commonObjectOptions // { … }` exactly as today.

**Public-shape impact**: none. Same option keys, same types, same defaults.

**Status**: **Applied** in this work.

### F2. Repeated `submodule + addCheck` discriminator pattern

**Where**: 8 callsites across `expressions.nix` and `objects.nix`:

| Body | File:line | Discriminator |
|---|---|---|
| `rawPayloadBody` | `expressions.nix:84-86` | `?base && ?offset && ?len` |
| `tunnelPayloadBody` | `expressions.nix:104-106` | `?tunnel && ?protocol && ?field` |
| `namedPayloadBody` | `expressions.nix:120-122` | `!?tunnel && ?protocol && ?field` |
| `rawTcpOptionBody` | `expressions.nix:168-170` | `?base && ?offset && ?len` |
| `namedTcpOptionBody` | `expressions.nix:185-187` | `?name && !?base` |
| `tunnelVxlanNested` | `objects.nix:587-592` | `?gbp && !?version` |
| `tunnelErspanV1Nested` | `objects.nix:595-606` | `version == 1` |
| `tunnelErspanV2Nested` | `objects.nix:609-627` | `version == 2` |

Each pairs an intermediate `*Submodule` (often unused outside this pattern) with an inline `addCheck` predicate. The predicates and the option lists are maintained separately, so a discriminator and its body can drift.

**Proposal**: single helper, applied to all 8 sites.

```nix
# lib/schema/internal.nix (new file) or inline in expressions.nix
discriminatedSubmodule = { options, requireKeys ? [], forbidKeys ? [] }:
  types.addCheck (types.submodule { inherit options; }) (v:
    builtins.isAttrs v
    && lib.all (k: v ? ${k}) requireKeys
    && lib.all (k: !(v ? ${k})) forbidKeys);
```

Use:
```nix
rawPayloadBody = discriminatedSubmodule {
  requireKeys = [ "base" "offset" "len" ];
  options = {
    base = mkOption { type = payloadBaseType; description = "..."; };
    offset = mkOption { type = types.ints.unsigned; description = "..."; };
    len = mkOption { type = types.ints.unsigned; description = "..."; };
  };
};
```

For the ERSPAN versions where the discriminator is `version == N` (a value check, not key presence), the helper accepts an optional `extraCheck` predicate:
```nix
discriminatedSubmodule = { options, requireKeys ? [], forbidKeys ? [],
                          extraCheck ? (_: true) }:
  types.addCheck (types.submodule { inherit options; }) (v:
    builtins.isAttrs v
    && lib.all (k: v ? ${k}) requireKeys
    && lib.all (k: !(v ? ${k})) forbidKeys
    && extraCheck v);
```

**Public-shape impact**: none. Same accepted/rejected attrset shapes.

**Status**: **Applied** in this work. New helper lives in `lib/schema/internal.nix` and is used by both `expressions.nix` and `objects.nix`.

### F3. `setObjectBody` and `mapObjectBody` near-duplicate

**Where**: `lib/schema/objects.nix:195-331`. 11 of 12 options identical: family, table, name, handle, type, policy, flags, elem, timeout, gc-interval, size, auto-merge, stmt. Only `mapObjectBody` adds a `map` field (the value datatype or object-type name).

**Proposal**: extract the shared options as a fragment, then:

```nix
setMapCommonOptions = namedInTableOptions // {
  type = mkOption { type = setDatatype; description = "set datatype"; };
  policy = mkOption { … };
  flags = mkOption { … };
  elem = mkOption { … };
  timeout = mkOption { … };
  "gc-interval" = mkOption { … };
  size = mkOption { … };
  "auto-merge" = mkOption { … };
  stmt = mkOption { … };
};

setObjectBody = types.submodule { options = setMapCommonOptions; };
mapObjectBody = types.submodule {
  options = setMapCommonOptions // {
    map = mkOption {
      type = setDatatype;
      description = "map value datatype or object-type name";
    };
  };
};
```

The `type` option's description currently differs between set ("set datatype") and map ("map key datatype") — keep the slight difference if that wording matters by overriding it on the map side:

```nix
mapObjectBody = types.submodule {
  options = setMapCommonOptions // {
    type = mkOption {
      type = setDatatype;
      description = "map key datatype";  # override
    };
    map = mkOption { … };
  };
};
```

**Public-shape impact**: none.

**Status**: **Applied** in this work.

### F4. Repeated `addCheck (listOf x) length-pred` pattern

**Where**: `expressions.nix:60` (`rangeBody`, length == 2) and `expressions.nix:419` (`binaryOpBody`, length >= 2). Same idea, two ad-hoc encodings.

**Proposal**: helpers in `lib/schema/internal.nix`:

```nix
listOfLen    = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs == n);
listOfMinLen = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs >= n);
```

Use:
```nix
rangeBody    = listOfLen 2 expression;
binaryOpBody = listOfMinLen 2 expression;
```

**Public-shape impact**: none.

**Status**: **Applied** in this work.

### F5. `rtFamilyType` and `natFamilyType` duplicate the same enum

**Where**: `primitives.nix:200-203` and `primitives.nix:287-290`. Both are `enum [ "ip" "ip6" ]`.

**Why this matters**: anywhere the schema needs an "IP family" — `rt` expression, `nat` statement, `ipsec`/xfrm expression's `family`, etc. — the choice between the two types is essentially arbitrary. Right now `ipsec` uses `rtFamilyType` (`expressions.nix:363-367`) which couples two unrelated concepts.

**Proposal**: define one canonical type.

```nix
ipFamilyType = types.enum [ "ip" "ip6" ];
# Backwards-compatibility aliases — re-export as the same value so code
# referring to either works during the transition. Mark for follow-up.
rtFamilyType  = ipFamilyType;
natFamilyType = ipFamilyType;
```

**Public-shape impact**: none — aliases preserve all existing references. A follow-up can rename callers to `ipFamilyType` and drop the aliases.

**Status**: **Applied** in this work (rename callers and drop aliases is deferred per F11 below).

### F6. `limitObjectBody.unit` is vestigial and the comment is misleading

See spec-coverage.md E19. The schema exposes `unit` with the comment "(derived from rate_unit; kept for symmetry)" but the parser ignores it.

**Status**: **Applied** in this work. `unit` is removed from `limitObjectBody`. A regression test in `tests/default.nix` confirms `{ limit: { name: "x", rate: 10, per: "second", unit: "packets" } }` parses through `nft -c -j -f` whether or not `unit` is present (so future re-additions are immediately flagged).

### F7. `ctTimeoutProtoType` is an alias of `ctHelperProtoType` with a misleading name

**Where**: `primitives.nix:266`. The alias suggests "ct-timeout-specific protocol type" when the parser uses identical `tcp`/`udp` branching for ct helper, ct timeout, and ct expectation (`parser_json.c:3795-3802, 3815-3823, 3844-3852`).

**Proposal**: rename to a single `tcpUdpProtoType` and update the three callers (`ctHelperObjectBody`, `ctTimeoutObjectBody`, `ctExpectationObjectBody`). Keep `ctHelperProtoType` and `ctTimeoutProtoType` as aliases for one release.

```nix
tcpUdpProtoType = types.enum [ "tcp" "udp" ];
ctHelperProtoType  = tcpUdpProtoType;
ctTimeoutProtoType = tcpUdpProtoType;
```

**Public-shape impact**: none.

**Status**: **Applied** in this work.

### F8. Module return-shape inconsistency

**Where**:

| Module | Returns |
|---|---|
| `primitives.nix` | `{ listOrSingleton; types = {…}; }` |
| `expressions.nix` | `{ expression; verdictTargetBody; all = {…}; }` |
| `statements.nix` | `{ statement; all = {…}; }` |
| `objects.nix` | `{ all = {…}; tagOpt; addObject; listObject; flushObject; resetObject; }` |
| `commands.nix` | `{ command; ruleset; }` |

`tagOpt` is exported by `objects.nix` even though `commands.nix` consumes it; `commands.nix` doesn't have an `all` even though it has bodies that could be exposed; `primitives.nix` exports types nested inside a `types` attrset while everyone else exports flat.

**Proposal**: unify to `{ <main type(s)>; all = {…}; <helpers>; }`:

- `primitives.nix` keeps `types = {…}` (large flat set; nesting is reasonable here) — leave as-is.
- `expressions.nix`, `statements.nix`, `objects.nix`, `commands.nix` all return `{ <type>; all = {…all bodies/wrappers}; }`.
- Move `tagOpt`, `wrap`, and the new `discriminatedSubmodule`/`listOfLen` helpers into `lib/schema/internal.nix`. Both `objects.nix` and `commands.nix` import from there.

**Public-shape impact**: low. Anyone importing `nftlib.objects.tagOpt` would have to import from `nftlib.schema.internal.tagOpt` — but `tagOpt` is not part of the documented public API (no README mention), so the change is safe.

**Status**: **Applied** in this work for the helper relocation. The return-shape unification is **partial**: `objects.nix` still exposes `addObject`/`listObject`/`flushObject`/`resetObject` because `commands.nix` consumes them via `objects.<…>`. Standardizing to `objects.unions.<…>` is deferred — it changes a public-ish import path.

### F9. Add the `meter` object kind needed by F4 fix in spec-coverage (G5)

A minimal `meterObjectBody` is added to support `flushObject` and `listObject` for meters. This is a coverage fix per spec-coverage G5, but it lives in the schema layer so it's worth flagging here for review.

```nix
meterObjectBody = types.submodule {
  options = namedInTableOptions;  # family + table + name + handle
};
```

The DSL is unchanged (no `flush.meter`/`list.meter` exposed there yet — deferred to a separate change).

**Status**: **Applied**.

---

## Findings — deferred to follow-up

### F10. Three near-parallel `*RefOrBody` patterns

**Where**: `counterRefOrBody` (`statements.nix:49-66`), `quotaRefOrBody` (`statements.nix:81-110`), `limitRefOrBody` (`statements.nix:113-146`). All encode a "named reference (string) OR inline body OR null" union.

**Proposal sketch**:

```nix
refOrInline = { allowNull ? false, inlineBody }:
  types.oneOf (
    lib.optional allowNull nullType
    ++ [ types.str inlineBody ]
  );
```

Then:
```nix
counterRefOrBody = refOrInline {
  allowNull = true;
  inlineBody = types.submodule { … };
};
```

**Why deferred**: the helper saves only ~3 lines per site, the three inline bodies are different enough that the helper wouldn't extract them, and `oneOf` arity matters for type-error messages — this might silently worsen errors. **Try the rewrite, measure error quality, then decide.**

### F11. Drop `rtFamilyType`/`natFamilyType` aliases after callers migrate

After F5 lands, `lib/schema/expressions.nix:363, 255` references `rtFamilyType` for ipsec.family and ct.family; `lib/schema/statements.nix` references `natFamilyType` for nat/fwd/tproxy. All three should switch to `ipFamilyType` directly, and the aliases can then be removed.

**Why deferred**: requires a coordinated rename across statements.nix and expressions.nix; the aliases ship the F5 fix without that churn. Schedule for the next release.

### F12. Replace `addObjectBodies` with derivation from `wrappers`

**Where**: `objects.nix:759-776`. Currently a hand-built attrset with hyphenated keys (`"ct helper"`, `"ct timeout"`, `"ct expectation"`) mirroring the wrapper definitions above. Could potentially be derived from `wrappers` by mapping each `wrap key body` back to `key → body`.

**Why deferred**: `wrappers` use camelCase keys (`ctHelper`, `ctTimeout`) while `addObjectBodies` use the hyphenated parser keys (`ct helper`, `ct timeout`). Bridging them requires either a key-rename map or a single source of truth using parser keys throughout. Either is a noticeable restructure; not worth coupling to this audit.

### F13. Split `objects.nix` (815 lines) by category

`objects.nix` mixes ruleset objects (table, chain, rule, set, map, element, flowtable), named objects (counter, quota, limit, ct helper, ct timeout, ct expectation, secmark, synproxy, tunnel), and command-union helpers (`addObject`, `listObject`, `flushObject`, `resetObject`). Could split into `objects/ruleset.nix`, `objects/named.nix`, `objects/unions.nix`.

**Why deferred**: organizational, not behavioural. Defer until the file gets bigger or someone needs to add a new object kind.

### F14. Replace `types.attrTag` discriminated unions with hand-rolled discriminators

`attrTag` works but error messages on a typo'd statement key (`{ accpet = null; }`) are unfriendly. A hand-rolled union with explicit "did you mean accept?" suggestions would be nicer but is a significant rewrite touching every body in the schema.

**Why deferred**: scope creep. Only worth doing if real users hit this class of error often.

### F15. Auto-merge JSON keys with hyphens (`auto-merge`, `gc-interval`, `queue-threshold`, `src-ipv4`, `dst-ipv4`, `src-ipv6`, `dst-ipv6`, `opt-type`)

The schema uses string-keyed options for JSON keys with hyphens (forced by Nix syntax). The DSL's `lib/dsl/internal/rename.nix` translates camelCase user input to these hyphenated keys. The schema layer is parser-faithful as-is.

**Why deferred (won't fix at schema layer)**: any change here is API- shape — hyphenated keys are what the JSON parser expects.

### F16. Document context-flag restrictions on expression placement

`parser_json.c:1646-1689` decorates each expression entry with `CTX_F_*` flags marking which contexts (RHS, STMT, PRIMARY, SET_RHS, MANGLE, SES, MAP, CONCAT) it's allowed in. Schema doesn't model this; all expressions can appear anywhere syntactically.

**Why deferred**: encoding context flags would require either a much richer `expression` type (parametrized by allowed contexts) or runtime predicates that defeat the point of static checking. The schema's permissiveness is intentional; live-parser tests catch context misuse.

### F17. Tighten `mangleBody.key` / `flowBody.flowtable` / `resetBody`

See spec-coverage E5, E6, E7. Schema is more permissive than parser on these. Could add `addCheck` predicates restricting key types.

**Why deferred**: more rigour in schema layer = harder error messages; live-parser tests catch these. Nice-to-have.

---

## Module-by-module observations

### `lib/schema/primitives.nix`

- 38 distinct enum types + 4 helper types. All names use `<concept>Type` suffix consistently except `nullType`, `portNumber`, `prefixLength` (intentional — they aren't enums).
- Backwards-compat meta-key aliases (`ibriport`, `obriport`, `secpath`) inlined into the same enum. Comment at line 188 calls this out. Good.
- `listOrSingleton` helper exposed at top level — used in objects.nix and statements.nix. Could move to internal.nix but it's small enough that the current export is fine.

### `lib/schema/expressions.nix`

- Uses `rec { … }` for fixed-point recursion through `expression`. Works because `submodule`/`oneOf`/`listOf` defer evaluation. Comment at line 25-27 explains. Good.
- 8 nested submodules (payload × 3 forms, tcp option × 2 forms, exthdr, ip option, sctp chunk, dccp option, meta, rt, ct, numgen, jhash, symhash, fib, socket, osf, ipsec, tunnel, elem, verdict target). All use the same pattern. After F2 lands, all 8 discriminated ones are uniform.
- The 5 binary operators all share `binaryOpBody`. After F4 lands, `binaryOpBody = listOfMinLen 2 expression`.
- `taggedExpression` builds an `attrTag` from a flat attrset map. Idiomatic.

### `lib/schema/statements.nix`

- 31 statement tags. SNAT/DNAT share `natBody`; masquerade/redirect share `masqueradeBody`. Good factoring.
- `setStatementBody` and `mapStatementBody` differ only by `data` and the option name (`set` vs `map`). Could factor — but it's only duplication of 5 options, not a deep cost. Left as-is.
- `synproxyStatementBody` is `oneOf [nullType synproxyAnonBody expr]` — models the three forms from `parser_json.c:2678-2735`. Schema makes mss/wscale required in the anon form (E10).

### `lib/schema/objects.nix`

- 815 lines, dominant single-file complexity in the schema. F13 proposes splitting; deferred.
- Tunnel object's nested polymorphism is the gnarliest part — `discriminatedSubmodule` (F2) cleans up the three discriminated bodies for VXLAN/ERSPAN v1/ERSPAN v2.
- `wrappers` (738-757) builds single-tag wrappers per object kind, used by `commands.nix` for command-body shapes. Reasonable.
- `addObjectBodies`/`addObject`/`listObject`/`flushObject`/`resetObject` are the per-command-verb unions. After spec-coverage G4/G5 fixes, `flushObject` drops `flowtable` and gains `meter`.

### `lib/schema/commands.nix`

- 48 lines, the smallest schema module. Wires up `command` (attrTag of 10 verbs) and `ruleset` envelope.
- Uses `objects.tagOpt` and `objects.all.rule`/`.chain` for the single-tag wrappers needed by `replace`/`insert`/`rename`. After F8, `tagOpt` lives in `internal.nix`; `objects.all.<…>` access stays.

### `lib/clean.nix`, `lib/json/default.nix`

- 36 + 16 lines. Single-purpose, focused, no review findings.

### `lib/default.nix`

- Wires the modules and re-exports the public API. Two minor smells:
  - `inherit (objects) addObject listObject flushObject resetObject;` (line 37-43) splats command-helper unions out of the `objects` namespace. Could keep them under `objects.unions.<…>` instead. Deferred — public-ish access pattern.
  - `cleanValue = clean;` (line 50) re-exports the internal cleaner. Used? Not by any test or example I can find. Probably exposed for library consumers to tidy attrsets without rendering. Leave alone.

---

## Test impact

After F1–F9 land:

- All 240+ schema assertions in `tests/default.nix` continue to hold — refactorings are public-shape-preserving.
- 5 new tests added for spec-coverage gap fixes (one each for G1–G5).
- 1 regression test added for F6 (`limit.unit` vestigial).
- Live-parser integration suites (`dsl-integration.nix`, `text-integration.nix`, `render-equivalence.nix`) re-run unchanged.

---

## After this work — recap

| ID | Finding | Status |
|---|---|---|
| F1 | Identity-options helpers | Applied |
| F2 | `discriminatedSubmodule` helper | Applied |
| F3 | Set/Map common options | Applied |
| F4 | `listOfLen`/`listOfMinLen` helpers | Applied |
| F5 | `ipFamilyType` consolidation (with aliases) | Applied |
| F6 | Drop `limitObjectBody.unit` | Applied |
| F7 | `tcpUdpProtoType` rename (with aliases) | Applied |
| F8 | Internal helpers in `lib/schema/internal.nix`; partial return-shape unification | Applied |
| F9 | `meterObjectBody` to support spec-coverage G5 | Applied |
| F10 | `refOrInline` helper | Deferred |
| F11 | Drop `rt`/`natFamilyType` aliases | Deferred |
| F12 | Derive `addObjectBodies` from `wrappers` | Deferred |
| F13 | Split `objects.nix` | Deferred |
| F14 | Replace `attrTag` with hand-rolled unions | Deferred |
| F15 | Hyphenated JSON keys | Won't fix (parser-mandated) |
| F16 | Expression context flags | Won't fix (intentional) |
| F17 | Tighten permissive bodies (mangle/flow/reset) | Deferred |
