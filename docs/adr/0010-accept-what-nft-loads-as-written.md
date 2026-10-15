# Accept what nft loads as written, and refuse what it loads otherwise

The schema accepts every form that the `nft` parser of a tested package set (the lock or a policy Pin) accepts, plus every shape its Read-back emits. It rejects a form that `nft` accepts but loads as something other than it says, because a silent change to a firewall is worse than an error. Each such form is a Known difference, and a live test asserts that `nft` still misbehaves, so a fixed `nft` fails the test and the form can return.

## Considered options

- Accept exactly what the parser accepts. nftables 1.1.6 loads a chain with `hook` but no `type` or `prio` as a regular chain, deletes the whole table for `delete ct expectation`, and writes a tunnel's `dport` into its `sport`; mirroring the parser would let validated values do the same.
- Accept only what the locked `nft` accepts. It would drop the `ct count` object, which only the unstable Pin's nftables 1.1.7 has.

## Consequences

- A form that only a newer tested `nft` accepts stays in the model, and live suites expect its rejection on the older `nft` instead of skipping it.
- Read-back shapes are accepted even where `nft` ignores them on input, such as element statements; the text renderer refuses those (ADR 0001).
- Raw attrsets still reach `nft` unvalidated (ADR 0003), so these rejections protect validated values only.

## Evidence

- nftables 1.1.6 and 1.1.7 `src/parser_json.c`: the chain parser unpacks `type`, `hook`, and `prio` as one optional group; `json_parse_cmd_add_object` passes the kernel object number as the command object type for `delete`, `list`, and `destroy`; the tunnel parser assigns `dport` to `tunnel.sport`; `json_parse_set_elem_expr` reads only `val`, `timeout`, `expires`, and `comment`.
