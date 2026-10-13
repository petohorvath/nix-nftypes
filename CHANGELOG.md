# Changelog

All notable changes to nix-nftypes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-13

First release. The [API reference](docs/api.md) documents every export below, and the [glossary](GLOSSARY.md) defines the project's terms.

### Added

- Schema types under `types` that model libnftables JSON and validate attrsets through `lib.evalModules`:
  - `ruleset`, the `{ nftables = [ … ]; }` envelope, and `command`, one `add`, `create`, `insert`, `replace`, `delete`, `destroy`, `list`, `flush`, `reset`, or `rename` command.
  - `expression`, `statement`, and the per-variant submodules under `types.expressions`, `types.statements`, and `types.objects`, including the named `ct count` object from nftables 1.1.7.
  - `statementOf` and `expressionOf`, which restrict an option to selected tags.
  - Primitive types such as `family`, `hook`, `chainType`, `ifname`, and `nftQuotedString`, with the values of each enum type under `enums`.
- A DSL under `dsl` that builds the same schema-shaped values:
  - Field leaves such as `fields.tcp.dport` and `fields.ct.state`, the raw `payload` helpers, and expressions under `dsl.expr`, such as `concat`, `prefix`, `range`, `set`, `map`, and `jhash`.
  - Match operators such as `eq`, `inSet`, and `within`, verdicts, and statements such as `counter`, `limit`, `log`, `dnat`, and `meter`. The `counter`, `quota`, `limit`, `synproxy`, and `ctCount` statements reference a named object by name or through a map expression (`quota.ref (expr.map { … })`).
  - `dsl.table`, a declarative tree of one table's chains, ordered rules, and named objects. It checks each entry's scope against its table and chain, and validates every assembled body against the schema when output is requested.
  - `dsl.ruleset` and the command builders `flush*`, `rule`, `create`, `delete`, `destroy`, `list`, `reset`, `replace`, `insert`, and `rename.chain`.
- Renderers, pure functions that neither call `nft` nor validate their input:
  - `toJson`, libnftables JSON for `nft -j -f`, and `toNix`, Nix syntax for inspection, both after `cleanValue` normalization.
  - `toText` and `toTextPretty`, imperative nftables text for `nft -f`.
  - `toTextBlock` and `toTextBlockPretty`, the contents of one `dsl.table` without the `table { … }` wrapper, the form that `networking.nftables.tables.<name>.content` takes.
  - The text renderers refuse a string that nftables text cannot carry, such as a comment containing `"`, instead of escaping it ([ADR 0004](docs/adr/0004-refuse-unsafe-text.md)).
- Compatibility helpers `resolvePriority`, `priorityNameOf`, `chainTypeFor`, and `validChainPlacement`, and the static family, chain-type, hook, and priority tables under `compatibility`.
- Error messages prefixed with the project name, `nix-nftypes:`.
- `packages.<system>.nftables-source`: the nftables release source with every nixpkgs patch applied, which is the source the nixpkgs `nft` binary is built from.
- Checks for `x86_64-linux` and `aarch64-linux`, run with nix-unit:
  - Evaluation-only unit suites.
  - Live tests that, inside a NixOS VM, check rendered JSON and text with the nixpkgs `nft`, load them, and compare the read-back rulesets.
  - Source tests that check the schema against the patched nftables source: the enum tables and tags extracted from the parser, the upstream statement corpus in `tests/py`, and the source's provenance against the `nft` binary.
- CI through the [project policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.6/POLICY.md) `v0.6`, which builds every check with the locked `nixpkgs` and with the policy's stable and unstable pins. A daily workflow opens an issue when a pin's patched nftables source differs from the locked one ([`docs/upstream-sync.md`](docs/upstream-sync.md)).
- MIT license.

The schema follows the nftables that nixpkgs packages, 1.1.6 in the locked `nixos-26.05`, rather than upstream nftables; [`docs/spec-coverage.md`](docs/spec-coverage.md) lists the known differences. nftables 1.1.6 rejects `ct count` objects and references, so only the unstable pin's corpus check exercises them. Text output cannot represent every value that JSON can; [`docs/text-coverage.md`](docs/text-coverage.md) records the gaps.

[Unreleased]: https://github.com/petohorvath/nix-nftypes/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petohorvath/nix-nftypes/releases/tag/v0.1.0
