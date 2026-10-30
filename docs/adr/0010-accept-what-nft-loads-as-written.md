# Accept what nft loads as written, and refuse what it loads otherwise

The schema accepts every form that the `nft` parser of a tested package set (the lock or a policy Pin) accepts, plus every shape its Read-back emits. It rejects a form that `nft` accepts but loads as something other than it says, because a silent change to a firewall is worse than an error. Each such form is a Known difference, and a live test asserts that `nft` still misbehaves, so a fixed `nft` fails the test and the form can return.

## Considered options

- Accept exactly what the parser accepts. nftables 1.1.6 loads a chain with `hook` but no `type` or `prio` as a regular chain, deletes the whole table for `delete ct expectation`, and writes a tunnel's `dport` into its `sport`; mirroring the parser would let validated values do the same.
- Accept only what the locked `nft` accepts. It would drop the `ct count` object, which only the unstable Pin's nftables 1.1.7 has.

## Consequences

- A form that only a newer tested `nft` accepts stays in the model, and live suites expect its rejection on the older `nft` instead of skipping it.
- Read-back shapes are accepted in Read-back even where `nft` ignores them on input, such as element statements: `elemReadBackBody` takes them, `elemBody`, which input commands use, rejects them, and the text renderer refuses them (ADR 0001).
- The schema rejects five forms that `nft` loads as something else, each a Known difference with an `nft-misbehaviour` fixture:
  - a Selector field `nft` ignores for its verb, such as `elem` on `delete set`, which deletes the whole set instead of the elements;
  - `handle` on an `add`, `create`, or `rename` body, which `nft` ignores;
  - an element statement, such as a counter, in an input command, which `nft`'s JSON parser drops;
  - a set's or map's `comment` in an input command, which `nft`'s JSON parser drops;
  - a number as a stateful object Reference, such as `{ "ct helper" = 5; }`, which `nft` loads as a reference to the object named `"5"`.
- Every stateful object Reference is a name or a map expression. A number in a name position is likelier a mistake than a name, the string `"5"` still names that object, and `{ quota = 5; }` was already rejected. The schema also rejects forms `nft` refuses on load, which need no fixture: a Reference such as `{ secmark = true; }`, a `reset` of anything but a TCP option, a flowtable hook other than `ingress`, and a bare list as the data of a map lookup or vmap.
- Raw attrsets still reach `nft` unvalidated (ADR 0003), so these rejections protect validated values only.

## Evidence

- nftables 1.1.6 and 1.1.7 `src/parser_json.c`: the chain parser unpacks `type`, `hook`, and `prio` as one optional group; `json_parse_cmd_add_object` passes the kernel object number as the command object type for `delete`, `list`, and `destroy`; the tunnel parser assigns `dport` to `tunnel.sport`; `json_parse_set_elem_expr` reads only `val`, `timeout`, `expires`, and `comment`; and `json_parse_cmd_add_set` returns for `delete`, `destroy`, `list`, `flush`, and `reset` before it reads the set's other fields, `elem` included.
- The `nft-misbehaviour` cases in `tests/fixtures/nft-misbehaviour.nix` pin each Known difference that has a fixture: `delete-set-elem-deletes-whole-set` for a Selector field `nft` ignores, `add-handle-ignored` and `add-rule-handle-ignored-on-json` for a `handle` on an input body, `element-statements-ignored-on-json` for an element statement, `set-comment-ignored-on-json` for a set's or map's comment, and `number-reference-loads-as-name` for a number as a ct helper, ct timeout, ct expectation, or synproxy Reference; a secmark object needs SELinux, so the case leaves a secmark Reference out. `payload-l4proto-loads-header-field` covers the `l4proto` payload field, which `expr.payload` rejects because `nft` loads `ip l4proto 6` as `ip version 0 ip hdrlength 6`.
- The `rejectionCases` in `tests/fixtures/integration-cases.nix` check that `nft` and the schema both reject a boolean Reference (`boolean-object-reference`), a `reset` of anything but a TCP option (`reset-other-than-tcp-option`), and a flowtable hook other than `ingress` (`flowtable-hook-other-than-ingress`). The `anonymous-maps-from-lists` Integration case loads the anonymous map that replaces a bare list as map data, which nft rejects with "invalid mapping expression list". Measured on nftables 1.1.6 and 1.1.7, `{ "ct helper": 5 }` loads as a reference to the helper named `"5"`, and a number as a counter, quota, limit, ct timeout, ct expectation, or synproxy Reference loads the same way.
- The schema-side tests: `selectorTests`, `handleTests`, `elementStatementTests`, `testObjectReferencesRejectNumbersAndBooleans`, `testResetStmtRejectsOtherExpressions`, `testFlowtableHookIsIngressOnly`, `testVmapListDataRejected`, and `testMapLookupListDataRejected` in `tests/unit/schema.nix`.
