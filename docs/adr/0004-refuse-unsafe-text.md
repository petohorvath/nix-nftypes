# Refuse values that are not nft-safe instead of escaping them

nftables text has no escape syntax: the lexer ends a quoted string at the next `"`, treats `\` as a literal byte, and splits on newlines and other parser metacharacters. Escaping cannot work, so the project refuses such values: schema types such as `comment` and `ifname` reject them at evaluation, and the text renderer asserts the same shared predicates as defence in depth for raw attrsets that bypass the schema. A comment containing `"` had rendered to text that `nft -f` loaded as an extra `policy accept` chain, a full firewall bypass.

## Consequences

- JSON can carry values that the text path refuses; `docs/text-coverage.md` documents this.
- The text renderer checks every string it emits, closed-set fields such as `policy` included, because a raw attrset can put any string in any position.
- Quoting is not escaping. The text renderer quotes a value it knows to be an interface name, so the ifname predicate needs only the quoted-string rules and the kernel's own name rules; where the renderer cannot tell, it keeps the stricter bare-token check and refuses a string that nft's lexer would read as something other than that string, such as `010`.
- nft expands `$name` inside a quoted `log prefix` and has no escape for `$`, so the log-prefix predicate rejects every `$`.
- Every Refusal starts `nix-nftypes: text: refusing to render …` and ends with `Field: <label>.`. The label names the position as nft does: the statement, expression, or object kind, then the field, by its JSON key or in nft's words (`chain policy`, `limit rate_unit`, `map element value`), with `object` where a statement shares the kind's name (`quota object bytes`), and `expression` where the renderer knows no position. It is never a dotted DSL path, which the DSL's own errors use ([ADR 0009](0009-dsl-naming-and-argument-conventions.md)), because a raw attrset reaches the renderer without one.
- Where the schema cannot express the constraint, the renderer is the only guard. A constrained string branch on `expression` hit an infinite recursion in nixpkgs' `oneOf`, so expression scalars are checked only at render time (`3cb7bf9`).

## Evidence

- `12df5f1` replaces the old escaping with a throw and adds the comment type, now `types.comment`; `acb1d78`, `3cb7bf9`, `26372a3`, `fbb0a55`, `c869ae7`, `4a288f5`, `9f964ba`, and `aab9d4b` apply the same rule to the other text positions.
- The shared predicates in `lib/nft-safe-string.nix`, `lib/nft-safe-scalar.nix`, and `lib/nft-safe-ifname.nix`; `1b6b7a4` makes each refusal name its field.
