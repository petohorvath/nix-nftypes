# Spec coverage audit — nft-types vs `parser_json.c`

This doc records a file-by-file comparison of `lib/schema/` against `src/parser_json.c` in the nftables source tree. The README's "How this was built" section asserts the schema is **1:1 with `parser_json.c`** (not with the `libnftables-json(5)` adoc). This audit verifies that claim, lists every deviation between the adoc and the parser that the schema captures, and tracks gaps and edge cases.

- **nftables version audited**: HEAD `f7dc8269` (2026-04-22), via README pin `0960e9001ed` (2026-04-17). The two intervening commits touch `evaluate.c` and Python tests only — no schema-relevant change. README pin is bumped to `f7dc8269` in this work.
- **Authoritative parser**: `../nftables/src/parser_json.c` (4716 lines).
- **Authoritative serializer (round-trip)**: `../nftables/src/json.c` (2268 lines).
- **Adoc spec (reference, not authority)**: `../nftables/doc/libnftables-json.adoc`.

## Coverage summary

| Category    | In parser | In schema | Gaps             | Notes                           |
|-------------|-----------|-----------|------------------|---------------------------------|
| Object kinds (singular) | 16 + ruleset + metainfo | 16 + ruleset + metainfo | 0 | All `add`-able object kinds modelled. |
| Object kinds (plural list/reset forms: `tables`, `chains`, `sets`, `counters`, …) | 13 | 0 | 13 | Read-back shapes only; never used as input. **Documented edge case** — not a fix target. |
| Statements              | 31 (incl. `vmap` aliased and `xt` rejected) | 31 | 0 | All statement tags modelled. `xt` modelled but parser rejects (edge case). |
| Expression tags         | 30 (concat/set/map/prefix/range, payload, exthdr, tcp/ip/sctp/dccp option, meta/rt/ct/fib/socket/osf/ipsec/tunnel/elem, numgen/jhash/symhash, 5 binops, 6 verdicts) | 30 | 0 | Match. |
| Enums (`primitives.nix`)  | 30 distinct lookup tables | 38 enum types in schema | 3 enum-value gaps | See "Enum coverage" below. |
| Commands                | 10 (`add` `replace` `create` `insert` `delete` `destroy` `list` `reset` `flush` `rename`) + bare-listed implicit | 10 + topLevel union | 0 | Match. |

**Enum-value gaps confirmed**: 3 (rt key `ipsec`, osf key `version`, fib result `check`). **Object-shape gaps confirmed**: 2 (`flushObject` includes `flowtable` parser rejects; missing `meter`). Total gaps fixed in this work: 5. See "Confirmed gaps" below.

## Methodology

Every `json_parse_*` function in `parser_json.c` was read in full and mapped to its schema counterpart in `lib/schema/`. For each parser function:

- `json_unpack_err(ctx, root, "{s:X}", "key", &dst)` → required field with type derived from format char (`s` string, `i` int, `I` int64, `b` bool, `o` recursive object). `_err` calls fail the parse if the key is missing.
- `json_unpack(root, "{s:X}", "key", &dst)` → optional field, missing key silently leaves `dst` at its initial value (often a documented default).
- Enum lookup tables (typically a `static const struct { name, val } tbl[]` or a `parse_*_flag` helper) define the exhaustive set of accepted strings.

Every accepted string-equality branch (`if (!strcmp(key, "..."))`) and every entry in a flag/key table was cross-checked against `lib/schema/primitives.nix` and the relevant body type.

---

## Confirmed gaps

These are cases where the parser accepts something the schema rejects.

### G1. `rtKeyType` missing `"ipsec"`

- **Parser**: `parser_json.c:993-997` — `rt_key_tbl[]` includes `{ "ipsec", NFT_RT_XFRM }`. JSON `{ "rt": { "key": "ipsec", "family": "ip" } }` is accepted.
- **Schema**: `lib/schema/primitives.nix:194-198` — `rtKeyType = enum [ "classid" "nexthop" "mtu" ]`. `"ipsec"` is rejected at evaluation time.
- **Origin**: NFT_RT_XFRM has been in `parser_json.c`'s `rt_key_tbl` since the table was introduced; the schema's enum was derived against `src/rt.c`'s `RT_TEMPLATE` table, which uses the same `"ipsec"` token (`src/rt.c:87`), but it was missed.
- **Fix in this work**: add `"ipsec"` to `rtKeyType`.

### G2. `osfKeyType` missing `"version"`

- **Parser**: `parser_json.c:486-489` —
  ```c
  if (!strcmp(key, "name")) { … }
  else if (!strcmp(key, "version")) {
      flagval |= NFT_OSF_F_VERSION;
      …
  }
  ```
- **Schema**: `lib/schema/primitives.nix:243-245` — `osfKeyType = enum [ "name" ]`.
- **Origin**: not derived from a lookup table; parser uses string-equality branches and the second branch was missed.
- **Fix in this work**: add `"version"` to `osfKeyType`.

### G3. `fibResultType` missing `"check"`

- **Parser**: `parser_json.c:1176-1182` — `fib_result_tbl[]` ends with `[__NFT_FIB_RESULT_MAX] = "check"` (a special form mapping to `NFT_FIB_RESULT_OIF` + `NFTA_FIB_F_PRESENT` flag). JSON `{ "fib": { "result": "check", "flags": ["saddr"] } }` is accepted.
- **Schema**: `lib/schema/primitives.nix:215-219` — `fibResultType = enum [ "oif" "oifname" "type" ]`.
- **Note**: the `"check"` form is semantically a "does this route exist?" predicate, not a value lookup. Useful in the wild (`tests/py/inet/fib.t`).
- **Fix in this work**: add `"check"` to `fibResultType`.

### G4. `flushObject` includes `flowtable` but parser does not

- **Parser**: `parser_json.c:4297-4304` — `cmd_obj_table[]` for flush has `table, chain, set, map, meter, ruleset` only. `flowtable` is *not* there; `nft -j -f` rejects `{ "flush": { "flowtable": … } }` with "Unknown object passed to flush command."
- **Schema**: `lib/schema/objects.nix:784-793` — `flushObject` includes `flowtable = bodies.flowtableBody;`.
- **Inconsistency**: README + `lib/dsl/` already document this. The DSL omits `flushFlowtable` deliberately ("nftables rejects `flush flowtable`, so that combination is intentionally absent" — README line 111). But the schema layer's `flushObject` exposes it anyway, so a hand-written `{ flush = { flowtable = …; }; }` passes type-check and then fails at `nft -c -j -f`.
- **Fix in this work**: drop `flowtable` from `flushObject`.

### G5. `flushObject` missing `meter`

- **Parser**: `parser_json.c:4302` — `{ "meter", CMD_OBJ_METER, … }` is in the flush dispatch table.
- **Schema**: `lib/schema/objects.nix:784-793` — no `meter` entry in `flushObject` (and no `meterBody` in `objects.nix` at all — meters are modelled as a *statement* in `statements.nix:325-345`, not as an object).
- **Note**: nftables represents anonymous meters internally as sets, which is why parser routes flush-meter to `json_parse_cmd_add_set`. A user listing a ruleset that contains a named meter and trying to flush it cannot do so via the schema.
- **Fix in this work**: add a minimal `meterObjectBody` (just family + table + name) and include it in `flushObject` (and `listObject` — see edge case E11). DSL exposure is deferred (DSL not in scope for this work).

---

## Adoc-vs-parser deviations the schema captures

Items the README "How this was built" section already notes are restated here in tabular form, plus newly verified items.

### Statements present in parser but absent from `libnftables-json(5)` adoc

| Statement | Parser fn | Adoc | Schema |
|---|---|---|---|
| `last`      | `json_parse_last_stmt` (1937) | absent | `statements.nix:402-409` ✓ |
| `flow`      | `json_parse_flow_offload_stmt` (2160) | absent | `statements.nix:411-422` ✓ |
| `tproxy`    | `json_parse_tproxy_stmt` (2364) | absent | `statements.nix:424-442` ✓ |
| `synproxy`  | `json_parse_synproxy_stmt` (2678) | absent | `statements.nix:444-466` ✓ |
| `reset`     | `json_parse_optstrip_stmt` (2866) | absent | `statements.nix:469` ✓ |
| `secmark`   | `json_parse_secmark_stmt` (2220) | absent | `statements.nix:511` ✓ |
| `tunnel`    | `json_parse_tunnel_stmt` (2237) | absent | `statements.nix:512` ✓ |

### Object types present in parser but absent from adoc

| Object | Parser branch | Adoc | Schema |
|---|---|---|---|
| `secmark`   | `json_parse_cmd_add_object:CMD_OBJ_SECMARK` (3767) | absent | `objects.nix:556-565` ✓ |
| `synproxy`  | `json_parse_cmd_add_object:CMD_OBJ_SYNPROXY` (3885) | absent | `objects.nix:567-583` ✓ |
| `tunnel`    | `json_parse_cmd_add_object:NFT_OBJECT_TUNNEL` (3902) | absent | `objects.nix:585-719` ✓ |

### Field-level deviations the schema follows the parser on

| Item | Parser | Adoc | Schema |
|---|---|---|---|
| `ct timeout` policy is a nested `{ state → seconds }` object | `parser_json.c:3550-3580` (`json_parse_ct_timeout_policy`) | flat `state` + `value` fields | `objects.nix:500-504` ✓ |
| `ct timeout` and `ct expectation` accept only `tcp`/`udp` for `protocol` | `parser_json.c:3815-3823, 3844-3852` | 8 protocols | `primitives.nix:266` (`ctTimeoutProtoType = ctHelperProtoType`) ✓ |
| `chain.dev` accepts a string OR `[string]` | `parser_json.c:3041-3079` (`json_parse_devs`) | string only | `objects.nix:140-145` (`listOrSingleton types.str`) ✓ |
| `flowtable.dev` accepts a string OR `[string]` | same `json_parse_devs` | string only | `objects.nix:383-387` ✓ |
| `comment` field on tables, chains, rules, named objects | `parser_json.c:2974, 3100, 3231, 3750` | absent on most kinds | present on all relevant kinds ✓ |
| `stmt` on sets/maps for stateful per-element statements | `parser_json.c:3423-3428` | absent | `objects.nix:253-257, 325-329` ✓ |
| `stmt` on the `set` and `map` *statements* (per-element on add/update) | `parser_json.c:2523-2526, 2583-2586` | absent | `statements.nix:255-258, 282-286` ✓ |
| `type_flags` on NAT statements (`interval`, `prefix`, `concat`) | `parser_json.c:2274-2289, 2353-2359` | absent | `statements.nix:203-207`, `primitives.nix:236-241` ✓ |
| `size` on `meter` statement | `parser_json.c:2793` | absent | `statements.nix:339-343` ✓ |
| `rate_unit`, `burst_unit`, `inv` on `limit` (statement and object) | `parser_json.c:2086-2089, 3868-3871` | partial coverage | `statements.nix:124-138, objects.nix:459-484` ✓ |
| `payload.base = "ih"` (inner-header) | `parser_json.c:668-669` | only `ll`/`nh`/`th` | `primitives.nix:229-234` ✓ |
| `socket.key = "mark"`, `"wildcard"` | `parser_json.c:506-509` | only `transparent` | `primitives.nix:252-256` ✓ |
| `nat.flag = "netmap"` | `parser_json.c:2263` | random/fully-random/persistent only | `primitives.nix:96-101` ✓ |
| `set.flag = "dynamic"` | `parser_json.c:3296` | constant/interval/timeout only | `primitives.nix:63-68` ✓ |
| `family = "egress"` hook | `chain_hookname_lookup`, kernel `nf_inet_hooks` | absent or partial | `primitives.nix:26-34` ✓ |
| `family = "arp"`, `"bridge"`, `"netdev"` | `parse_family` | partial in adoc | `primitives.nix:17-24` ✓ |
| Counter accepts `null` (stateless mode emit) | `parser_json.c:1914-1915` | not noted | `statements.nix:49-66` (`oneOf [nullType …]`) ✓ |
| Raw `tcp option` form (`{ base, offset, len }`) | `parser_json.c:745-765` | named only | `expressions.nix:152-189` ✓ |
| Tunnelled `payload` form (`{ tunnel, protocol, field }`) | `parser_json.c:686-712` | not mentioned | `expressions.nix:88-106` ✓ |
| Meta keys: `iifkind`, `oifkind`, `ibrpvid`, `ibrvproto`, `time`, `day`, `hour`, `secmark`, `sdif`, `sdifname`, `broute`, `ibrhwaddr`, `cgroup`, `ipsec` (=SECPATH), backwards-compat `ibriport`, `obriport`, `secpath` | `meta_templates[]` (`src/meta.c:617-708`) + `meta_key_parse` aliases (`src/meta.c:1020-1030`) | partial | `primitives.nix:150-192` (37 canonical + 3 aliases = 40) ✓ |
| `ipsec` (xfrm) expression — keys, family, dir, spnum 0-255 | `parser_json.c:1585-1644` | absent | `expressions.nix:357-379` ✓ |
| `tunnel` metadata expression (`path`/`id`) | `parser_json.c:446-461` | absent | `expressions.nix:381-386` ✓ |
| `ip option` expression (named form) | `parser_json.c:822-849` | absent | `expressions.nix:191-204` ✓ |
| `dccp option` expression | `parser_json.c:898-911` | absent | `expressions.nix:220-225` ✓ |
| `sctp chunk` expression | `parser_json.c:867-895` | mentioned briefly | `expressions.nix:206-218` ✓ |
| `osf` `version` key | `parser_json.c:486-488` | only `name` documented | **G2 above — missing in schema** |
| `rt.ipsec` key | `parser_json.c:997` | adoc mentions classid/nexthop/mtu | **G1 above — missing in schema** |
| `fib.result = "check"` | `parser_json.c:1181, 1201-1204` | not documented | **G3 above — missing in schema** |
| `connlimit` aliased as `ct count` | `parser_json.c:2917, json_parse_connlimit_stmt` | mentions `ct count` only | `statements.nix:503` ✓ |
| `flush meter` accepted | `parser_json.c:4302` | not documented | **G5 above — missing in schema** |
| `flush flowtable` rejected | `parser_json.c:4297-4304` (no `flowtable` row) | not documented | **G4 above — schema permits it** |

---

## Enum coverage

| Schema enum | Authoritative source | Status |
|---|---|---|
| `familyType` | `parse_family` | ✓ |
| `hookType` | `chain_hookname_lookup` (kernel `nf_inet_hooks` + `egress`) | ✓ |
| `policyType` | `parse_policy` (`parser_json.c:3006-3019`) | ✓ |
| `chainTypeType` | parser stores arbitrary string; valid set is `filter`/`nat`/`route` from kernel | ✓ |
| `operatorType` | `match` op `expr_op_symbols` for `OP_EQ..OP_NEG` + `"in"` (`parser_json.c:1873-1888`) | ✓ |
| `tableFlagType` | `parse_table_flag` → `table_flags_name[]` (`src/rule.c:1230-1234`: dormant/owner/persist) | ✓ |
| `setFlagType` | `string_to_set_flag` (`parser_json.c:3287-3305`: constant/interval/timeout/dynamic) | ✓ |
| `setPolicyType` | `parser_json.c:3385-3395` (performance/memory) | ✓ |
| `logLevelType` | `log_level_parse` (covers emerg…audit) | ✓ |
| `logFlagType` | `json_parse_log_flag` (`parser_json.c:2592-2604`) | ✓ |
| `natFlagType` | `json_parse_nat_flag` (`parser_json.c:2254-2272`) | ✓ |
| `natTypeFlagType` | `json_parse_nat_type_flag` (`parser_json.c:2274-2291`) | ✓ |
| `synproxyFlagType` | `json_parse_synproxy_flag` (`parser_json.c:2660-2676`) | ✓ |
| `flowOpType` | only `"add"` accepted (`parser_json.c:2169-2172`) | ✓ |
| `xfrmDirType` | `parser_json.c:1611-1620` | ✓ |
| `xfrmKeyType` | `xfrm_templates[]` (`src/xfrm.c`) | ✓ |
| `tunnelKeyType` | `tunnel_key_parse` (path/id) | ✓ |
| `queueFlagType` | `queue_flag_parse` (`parser_json.c:2815-2822`) | ✓ |
| `rejectTypeType` | `parser_json.c:2412-2429` | ✓ |
| `setOpType` | `parser_json.c:2494-2502, 2545-2553` | ✓ |
| `metaKeyType` | `meta_templates[]` + `meta_key_parse` aliases | ✓ |
| `rtKeyType` | `rt_key_tbl[]` (`parser_json.c:993-998`) | **G1 — missing `ipsec`** |
| `rtFamilyType` | `parse_family` restricted | ✓ |
| `ctDirectionType` | `parser_json.c:1077-1085` | ✓ |
| `ngModeType` | `parser_json.c:1107-1114` | ✓ |
| `fibResultType` | `fib_result_tbl[]` (`parser_json.c:1176-1182`) | **G3 — missing `check`** |
| `fibFlagType` | `fib_flag_parse` (`parser_json.c:1155-1170`) | ✓ |
| `payloadBaseType` | `parser_json.c:662-672` | ✓ (`ih` included) |
| `osfKeyType` | `parser_json.c:484-489` | **G2 — missing `version`** |
| `osfTtlType` | `parser_json.c:474-481` | ✓ |
| `socketKeyType` | `parser_json.c:504-510` (transparent/mark/wildcard) | ✓ — see E1 below |
| `ctHelperProtoType` | `parser_json.c:3795-3802` | ✓ |
| `ctTimeoutProtoType` | `parser_json.c:3815-3823, 3844-3852` (alias of `ctHelperProtoType` since the parser only branches tcp/udp for both) | ✓ |
| `xtTypeType` | schema models (match/target/watcher); parser **rejects all `xt`** (`parser_json.c:2942-2944`) | E2 below |
| `limitUnitType` | `rate_to_bytes` (kbytes/mbytes) + special `"packets"` | ✓ |
| `perUnitType` | `seconds_from_unit` (`parser_json.c:2063-2074`) | ✓ |
| `natFamilyType` | `parse_family` restricted | ✓ |

---

## Edge cases

Items where the parser does something the schema cannot or chooses not to enforce, or where parser/serializer behaviour is non-obvious.

### E1. Socket key `cgroupv2` exists in source but not in JSON parser

- `src/socket.c:37-40` defines `NFT_SOCKET_CGROUPV2 = "cgroupv2"`.
- `parser_json.c:495-518` (`json_parse_socket_expr`) only accepts `transparent`, `mark`, `wildcard`. `cgroupv2` is never read by the JSON path; it's reachable only via the `nft` text grammar (`parser_bison.y:5540-5542`).
- **Schema is correct** to omit `cgroupv2` from `socketKeyType` — parser fidelity wins. If/when upstream updates `json_parse_socket_expr`, this becomes a gap; tracked here to prompt a re-check on each version bump.

### E2. `xt` statement modelled but parser always rejects

- `parser_json.c:2942-2944`: `if (!strcmp(type, "xt")) { json_error(ctx, "unsupported xtables compat expression, use iptables-nft with this ruleset"); return NULL; }`
- Schema's `xtBody` (`statements.nix:389-400`) and `statement` tag (`statements.nix:504`) accept `{ xt = { type = …; name = …; }; }` and the resulting JSON serialises fine — but `nft -c -j -f` will reject it.
- **Decision**: keep schema as-is for round-trip with `nft -j list ruleset` output (which emits `xt` blocks for legacy rules) but document this asymmetry. Schema is intentionally broader than parser-input on this specific tag. **Add a comment** in `statements.nix:504` (deferred to a follow-up if not done in this PR).

### E3. `ct.key` is a free-form string, not an enum

- `parser_json.c:1062-1075` looks up the key against `ct_templates[]` (a large table in `src/ct.c`). The schema uses `types.str` rather than enumerating the table's tokens (`expressions.nix:248-265`).
- **Reasoning**: the ct_templates table is large and spread across kernel versions; mirroring it in Nix would be brittle. The schema accepts strings and lets the live parser reject invalid values. The same choice was made for `tunnel_key_parse` and `tunnel_type` lookups internally.

### E4. `ct.dir` always optional in schema but parser-conditional

- `parser_json.c:1077-1090` only accepts `dir` when `ct_key_is_dir(keyval)` is true. Schema marks `dir = nullOr ctDirectionType` unconditionally.
- **Reasoning**: schema can't easily encode the conditional without duplicating the entire `ct_dir_keys[]` table. Documented as permissive.

### E5. Mangle key MUST be exthdr/payload/meta/ct in parser

- `parser_json.c:1993-2018` (`json_parse_mangle_stmt`): the `key` expression `etype` is switched on; only `EXPR_EXTHDR | EXPR_PAYLOAD | EXPR_META | EXPR_CT` accepted. Schema accepts any expression in `mangleBody.key`.
- **Schema permissive** — invalid mangle targets will type-check but fail at `nft -c -j -f`.

### E6. `flow` statement requires flowtable name to start with `@`

- `parser_json.c:2174-2177`. Schema's `flowBody.flowtable = types.str` doesn't enforce the prefix.
- **Schema permissive**.

### E7. `reset` statement must wrap an `EXTHDR` of `OP_TCPOPT` kind

- `parser_json.c:2871-2877` (`json_parse_optstrip_stmt`): the inner expression must be `EXPR_EXTHDR && exthdr.op == NFT_EXTHDR_OP_TCPOPT`. Schema accepts any expression in `resetBody`.
- **Schema permissive**.

### E8. FIB flags have mutual-exclusion sanity checks

- `parser_json.c:1213-1230`: `(saddr,daddr)` pair must be set with exactly one; `(iif,oif)` pair if both set is rejected. Schema's `fibBody.flags = listOrSingleton fibFlagType` doesn't enforce these.
- **Schema permissive**.

### E9. Concat expression requires size >= 2

- `parser_json.c:1308-1320` (`json_check_concat_expr`). Schema's `concatBody = listOf expression` accepts any length including 0/1.
- **Schema permissive**.

### E10. Synproxy statement inline form: mss/wscale individually optional in parser, both required in schema

- `parser_json.c:2689-2710`: each of `mss` and `wscale` is read with `json_unpack` (optional). Setting only one is legal.
- Schema: `synproxyAnonBody` (`statements.nix:444-460`) makes both required.
- **Schema stricter than parser**. The synproxy *object* (`parser_json.c:3887`) requires both via `_err`, so the object-side schema is correct; only the *statement-side anonymous* form diverges. Probably intentional — partial-config synproxy statements are rarely useful — but worth noting if a user trips on it. Not fixed in this work.

### E11. Plural list/reset object kinds (`tables`, `chains`, `sets`, …) not modelled

- `parser_json.c:4127-4159` (`json_parse_cmd_list_multiple`) handles 13 plural keys for `list` (`tables`, `chains`, `sets`, `maps`, `counters`, `quotas`, `ct helpers`, `tunnels`, `limits`, `ruleset`, `meters`, `flowtables`, `secmarks`) and 3 for `reset` (`counters`, `quotas`, `rules`). These bodies have a different shape (just `family`, sometimes `table`) — they're read-back forms, not user-input.
- Schema's `listObject` and `resetObject` only model the singular kinds.
- **Decision**: treated as out of scope for parser-fidelity (the read-back shapes are rarely written by users). If round-trip parsing of `nft -j list ruleset` output containing plural-list forms is ever needed, a separate union (`listMultipleObject`?) can be added.

### E12. Tunnel object src/dst pair must be all-IPv4 or all-IPv6

- `parser_json.c:3649-3704` (`json_parse_tunnel_src_and_dst`): one src and one dst, both same family. Schema marks `src-ipv4`, `src-ipv6`, `dst-ipv4`, `dst-ipv6` as individually nullable.
- **Schema permissive**.

### E13. Tunnel object's nested `tunnel` field is type-dependent

- VXLAN/ERSPAN v1/ERSPAN v2/GENEVE — schema discriminates by key presence in the nested body but does not cross-validate against the sibling `type` field. Restated here from the original audit notes.

### E14. Upstream bug: `parser_json.c:3913` writes `dport` into `obj->tunnel.sport`

```c
json_unpack(root, "{s:i}", "sport", &i);
obj->tunnel.sport = i;
json_unpack(root, "{s:i}", "dport", &i);
obj->tunnel.sport = i;       // ← bug, should be dport
```

Schema correctly exposes both `sport` and `dport`; the fix has to land upstream. Tracked here so a future audit can confirm the bug is gone.

### E15. CT timeout `policy` state names are arbitrary strings

- `parser_json.c:3550-3580` accepts any string keys in the policy object; validation against the kernel's per-protocol state list happens later. The schema (`policy = nullOr (attrsOf ints.unsigned)`) matches the parser's permissiveness. Worth noting because the adoc would suggest stronger validation.

### E16. `setDatatype` accepts arbitrary strings for set/map type

- `parser_json.c:1815-1857` (`json_parse_dtype_expr`): a string goes through `datatype_lookup_byname`. For `map.map`, a string can also match `string_to_nft_object` (`parser_json.c:3265-3285`: `counter`, `quota`, `ct helper`, `limit`, `ct timeout`, `secmark`, `ct expectation`, `synproxy`, `tunnel`). Schema's `setDatatype = oneOf [str, listOf str, typeofBody]` permits any string.
- **Schema permissive** — typo-prone but matches the parser's approach (the parser does the lookup at parse time).

### E17. `*_unit` strings (rate_unit, val_unit, used_unit, burst_unit) are free-form strings in schema

- Parser accepts `"packets"` (special) plus `"bytes"`/`"kbytes"`/`"mbytes"` (passes through `rate_to_bytes`). Schema uses `types.str`. A typo like `"kibyte"` would silently pass schema and silently get treated as bytes by the parser (`rate_to_bytes` fall-through returns the value unchanged).
- **Schema permissive**. Could be tightened to an enum, but the current set isn't documented as the complete list — keep as-is.

### E18. Rule `index` field accepted by parser

- `parser_json.c:3214-3216, 4064-4066` reads `index`. Schema's `ruleBody.index` exposes it.
- **Confirmed match**; restated here because the adoc treats `handle` and `index` interchangeably.

### E19. `limitObjectBody.unit` field has no role in parser

- `parser_json.c:3861-3884` reads `rate`, `per`, `rate_unit`, `inv`, `burst`, `burst_unit`. The kernel-internal `limit.type` is derived from `rate_unit` (packets vs bytes), not from a separate `unit` field. The JSON serializer (`src/json.c`) emits `unit` as a synonym in some output paths but the parser silently ignores it.
- Schema exposes `unit` (`objects.nix:474-478`) marked "(derived from rate_unit; kept for symmetry)". Misleading — `unit` is not "derived" so much as **vestigial on the input side**.
- **Cleanup in this work**: drop `unit` from `limitObjectBody`; add a `tests/default.nix` regression test that confirms `nft -c -j -f` ignores `unit` so future re-additions are flagged.

### E20. `tableBody`/`chainBody`/`ruleBody` etc. carry `handle` for round-trip

- `nft -j list ruleset` emits `handle` on every read-back object. Schema marks `handle = nullOr ints.unsigned` so the same body type can describe both input (no handle) and output (with handle). Documented behaviour.

### E21. `chain.prio` is an integer only via the JSON path

- `parser_json.c:3124-3125`: `json_unpack(root, "{s:s, s:s, s:i}", "type", &type, "hook", &hookstr, "prio", &prio)` — `prio` is `s:i` (integer). Symbolic priorities (`filter`, `dstnat`, `mangle`, …) are a text-grammar feature only.
- Schema's `prio = nullOr types.int` is correct.

### E22. Implicit-add (bare object without command wrapper) for `nft -j list` round-trip

- `parser_json.c:4383-4393`: top-level objects without an outer command verb are treated as implicit `add` with `CTX_F_IMPLICIT` flag (which makes `handle` non-positional). Schema's `topLevel = oneOf [command, bareListObject]` (`commands.nix:34-37`) matches this.

---

## Round-trip / serializer notes (`src/json.c`)

The serializer was spot-checked for cases where output uses keys not on the input side (which would be parser-fidelity gaps from the `nft -j list ruleset` direction). Key findings:

- **`{counter: null}` stateless output**: `src/json.c` emits `null` for counter statements when the rule didn't carry counter values. Parser accepts (`parser_json.c:1914-1915`). Schema accepts via `counterRefOrBody` `oneOf [nullType …]`. Round-trip safe.
- **`metainfo` first object**: emitted as `{ "metainfo": { "version": "...", "release_name": "...", "json_schema_version": int } }`. Schema's `metainfoBody` matches.
- **`handle` echoed back on every object**: schema's nullable `handle` on every body type accepts these. Round-trip safe.
- **`elem` array entries**: emitted as either the bare value or `{ "elem": { "val": …, "timeout"?: int, "expires"?: int, "comment"?: str } }`. Schema handles both via `setElem = either expr (listOf expr)` for the container and `elemBody` for the tagged form.

No round-trip-only output keys discovered that the parser refuses on input.

---

## After this work — what changes

5 schema gaps are fixed in this work (G1–G5 above). The README claim "1:1 with `parser_json.c`" becomes literally true for everything except:

- E2 (`xt` statement modelled, parser rejects) — intentional, for round-trip with legacy `nft -j list` output.
- E5–E12, E15–E17 — parser is *stricter* than schema in places where the schema chose permissiveness over duplicating large lookup tables.
- E11 — plural-list-multiple forms not modelled (read-back only).

These remain documented divergences, by design.
