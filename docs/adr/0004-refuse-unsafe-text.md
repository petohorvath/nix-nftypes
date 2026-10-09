# Refuse values that are not nft-safe instead of escaping them

nftables text has no escape syntax: the lexer ends a quoted string at the next `"`, treats `\` as a literal byte, and splits on newlines and other parser metacharacters. Escaping cannot work, so the project refuses such values: schema types such as `nftQuotedString` and `ifname` reject them at evaluation, and the text renderer asserts the same shared predicates as defence in depth for raw attrsets that bypass the schema. A comment containing `"` had rendered to text that `nft -f` loaded as an extra `policy accept` chain, a full firewall bypass.

## Consequences

- JSON can carry values that the text path refuses; `docs/text-coverage.md` documents this.
- Where the schema cannot express the constraint, the renderer is the only guard. A constrained string branch on `expression` hit an infinite recursion in nixpkgs' `oneOf`, so expression scalars are checked only at render time (`3cb7bf9`).

## Evidence

- `12df5f1` replaces the old escaping with a throw and adds `nftQuotedString`; `acb1d78`, `3cb7bf9`, `26372a3`, `fbb0a55`, `c869ae7`, `4a288f5`, `9f964ba`, and `aab9d4b` apply the same rule to the other text positions.
- The shared predicates in `lib/nft-safe-string.nix`, `lib/nft-safe-scalar.nix`, and `lib/nft-safe-ifname.nix`; `1b6b7a4` makes each refusal name its field.
