# nix-nft-types

Strict Nix types, an ergonomic DSL, and pure renderers for nftables rulesets, checked against the nftables that nixpkgs packages.

## Model

**Schema**:
The Nix types that model libnftables JSON, from primitive enums up to a complete ruleset, including the shapes `nft` emits on read-back.
_Avoid_: type layer, nft-types layer

**Tag**:
The single attribute name that selects one variant of a statement or expression, such as `match` or `counter`.
_Avoid_: kind (for statements and expressions)

**Object kind**:
One of the things a command can add, delete, or list, such as a table, chain, rule, set, flowtable, or counter.
_Avoid_: object type

**Named object**:
An object kind other than a table, chain, or rule, declared by name inside a table and referenced by that name.

**Restricted type**:
A statement or expression type narrowed to a chosen set of tags, so a downstream option can reject every other tag.
_Avoid_: subset

**Placement**:
The family, chain type, and hook of a base chain taken together, which the static compatibility tables either allow or forbid.

**Symbolic priority**:
A named chain priority such as `filter` or `srcnat`, whose integer value depends on the family.

**Known difference**:
A documented place where the schema knowingly differs from the Authority: a parser form it rejects, a parser condition it leaves to `nft`, a read-back asymmetry, or a value the text grammar cannot spell.

## DSL

**DSL**:
The convenience layer that builds the same schema-shaped values with less repetition; it is not a second model.

**Field leaf**:
A pre-built expression for a common protocol or metadata field, such as the TCP destination port or the conntrack state.
_Avoid_: field (on its own), leaf (on its own)

**Variant namespace**:
A statement constructor that is callable for its common form and carries named variants for the others, such as `counter.auto` or `reject.icmpx`.
_Avoid_: callable attrset

**Table tree**:
A declarative description of one table: its options, its named objects, and its chains with their ordered rules.
_Avoid_: table node, declarative table structure

**Scope**:
The family, table, chain, and name that a body takes from its position in a table tree. Nesting owns scope; an explicit field that disagrees is a scope conflict.

**Expansion**:
Turning a table tree into an ordered list of commands: the table, its chains, its named objects, then its rules.

**Raw attrset**:
A hand-written value that the DSL did not build and nothing has validated; a raw attrset among a ruleset's commands is a raw command.

**Escape hatch**:
A lower-level path to a parser form the convenience API does not cover: a generic constructor, a `.raw` variant, or a raw attrset.

## Rendering

**Renderer**:
A pure function that turns a cleaned value into one output form without validating it or calling `nft`.
_Avoid_: serializer (that names nftables' own JSON output)

**Compatibility target**:
The output form whose acceptance by the Authority the project claims: JSON. Text is a secondary form with its own, narrower evidence.
_Avoid_: authoritative renderer

**Imperative form**:
nftables text written as top-level commands such as `add table` and `add rule`, for loading with `nft -f`.

**Block form**:
nftables text for the contents of one table, without its wrapper and with rules inside their chains, for a host that supplies the `table { … }` wrapper.
_Avoid_: block output, table-block output

**Cleaning**:
Removing module markers and unset optional fields from a value before rendering while keeping meaningful nulls. Cleaning is not validation.
_Avoid_: normalization

**Nft-safe**:
Of a string: emitted into nftables text, it parses as exactly the one token or quoted string intended. nftables text has no escape syntax, so a value that is not nft-safe is refused, never escaped.
_Avoid_: escaped

**Refusal**:
The error a renderer raises instead of emitting a value that is not nft-safe; it names the refused field.
_Avoid_: rejection (that is what the schema or the parser does)

## Upstream compatibility

**Package set**:
The packages of one nixpkgs revision, whose `nft` binary, patched nftables source, and `lib` a test run uses.
_Avoid_: channel

**Authority**:
What decides whether the model is right: the package set's `nft` binary and patched nftables source, and its `lib` for module validation.
_Avoid_: oracle

**Patched source**:
The nftables release source with every downstream nixpkgs patch applied, which is exactly what the packaged binary was built from.

**Corpus**:
nftables' own statement test cases, taken from the patched source, which the schema must accept.

**Baselined divergence**:
A named category of corpus statements that the schema knowingly rejects, recorded with its reason. The baseline lists every one; a category that no statement matches any more must be pruned.
_Avoid_: named pattern, known gap

**Drift**:
A difference between the Authority and the model, or between the locked and branch-tip patched source, that no Known difference accounts for yet.

**Branch tip**:
The newest revision of a tracked nixpkgs branch, resolved once to an immutable revision for one run.

**Source watch**:
The weekly job that compares each branch tip's patched source with the locked one and keeps a Drift issue open while they differ.

**Drift issue**:
The issue the Source watch keeps open for a branch while that branch tip's patched source differs from the lock; each branch has at most one.

**Canary**:
The weekly, non-gating run of the nftables-facing tests against each branch tip.

**Read-back**:
The JSON that `nft` emits when it lists loaded state, which the schema must also accept.
_Avoid_: round trip

**Render equivalence**:
The check that a case loaded through JSON and the same case loaded through text list the same ruleset.
_Avoid_: JSON/text equivalence

## Tests

**Live test**:
A test that runs the package set's real `nft` parser or loads rulesets into a kernel; live tests run as VM tests.

**Probe**:
A build step that runs `nft` or the source tooling and writes a Record without judging the result.

**Record**:
The JSON a Probe writes: each run's exit status and output, which a Suite then asserts on.
_Avoid_: observation

**Suite**:
A set of nix-unit tests. Evaluation-only suites assert on values; live suites assert on Records.

**Integration case**:
A named ruleset that the Live tests share.

**Named exclusion**:
An Integration case removed from one Live test before it runs, with the reason written in code.
_Avoid_: skip
