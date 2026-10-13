# Changelog

All notable changes to nix-nftypes will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-13

First release. The [API reference](docs/api.md) documents the library's exports, and the [glossary](GLOSSARY.md) defines the project's terms.

### Added

- Schema types under `types` that model libnftables JSON and validate attrsets through `lib.evalModules`:
  - `ruleset`, the `{ nftables = [ … ]; }` envelope, and `command`, one `add`, `create`, `insert`, `replace`, `delete`, `destroy`, `list`, `flush`, `reset`, or `rename` command.
  - `expression`, `statement`, and the per-variant submodules under `types.expressions`, `types.statements`, and `types.objects`, including the named `ct count` object from nftables 1.1.7.
  - `statementOf` and `expressionOf`, which restrict an option to selected tags.
  - Primitive types such as `family`, `hook`, `chainType`, `ifname`, and `nftQuotedString`, with the values of each enum type under `enums`.
- A DSL under `dsl` that builds the same schema-shaped values:
  - Field leaves such as `fields.tcp.dport` and `fields.ct.state`, the raw `payload` helpers, and expressions under `dsl.expr`, such as `concat`, `prefix`, `range`, `set`, `map`, and `jhash`.
  - Match operators such as `eq`, `inSet`, and `within`, verdicts, and statements such as `counter`, `limit`, `log`, `dnat`, `meter`, and `ctCount`. The `counter`, `quota`, `limit`, `synproxy`, and `ctCount` statements reference a named object by name or through a map expression (`quota.ref (expr.map { … })`).
  - `dsl.table`, which builds a table tree: one table's options, chains with their ordered rules, and named objects, such as `sets`, `counters`, and `ctCounts`. It checks each entry's scope against its table and chain, and validates every assembled body against the schema when output is requested.
  - `dsl.ruleset` and the command builders `flush*`, `rule`, `create`, `delete`, `destroy`, `list`, `reset`, `replace`, `insert`, and `rename.chain`, with a builder for each object kind, such as `create.ctCount`.
- Renderers, pure functions that neither call `nft` nor validate their input:
  - `toJson`, libnftables JSON for `nft -j -f`, and `toNix`, Nix syntax for inspection, both after cleaning (`cleanValue`).
  - `toText` and `toTextPretty`, imperative nftables text for `nft -f`. They render the `ct count` object as `ct count NAME { over|until N; }` and a map-expression reference as `quota name tcp dport map { … }`.
  - `toTextBlock` and `toTextBlockPretty`, the contents of one table tree without the `table { … }` wrapper, the form that `networking.nftables.tables.<name>.content` takes.
  - The text renderers refuse a string that is not nft-safe, such as a comment containing `"`, instead of escaping it ([ADR 0004](docs/adr/0004-refuse-unsafe-text.md)).
- Compatibility helpers `resolvePriority`, `priorityNameOf`, `chainTypeFor`, and `validChainPlacement`, and the static family, chain-type, hook, and priority tables under `compatibility`.
- Error messages prefixed with the project name, `nix-nftypes:`.
- `packages.<system>.nftables-source`: the patched source, the nftables release source with every nixpkgs patch applied, which the nixpkgs `nft` binary is built from.
- Checks for `x86_64-linux` and `aarch64-linux`:
  - Evaluation-only nix-unit suites.
  - Live tests, which run as VM tests with the nixpkgs `nft`. They parse selected JSON and text renderings with `nft -c`, load selected cases through JSON and through text and compare the listed rulesets, and validate the read-back of loaded cases against `types.ruleset`. The VM tests need KVM, so a plain `nix flake check` does too.
  - Source tests against the patched source: the enum tables and tags extracted from the parser, the upstream statement corpus, and the provenance of the source against the nixpkgs `nftables` package.
- CI through the [project policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.6/POLICY.md) `v0.6`, which builds every check with the locked `nixpkgs` and with the policy's stable and unstable pins. A daily source watch keeps a drift issue open for each pin whose patched source differs from the locked one ([`docs/upstream-sync.md`](docs/upstream-sync.md)).
- MIT license.

Known limits:

- The schema follows the nftables that nixpkgs packages, 1.1.6 in the locked `nixos-26.05`, rather than upstream nftables. [`docs/spec-coverage.md`](docs/spec-coverage.md) lists the known differences, and [`docs/dsl-coverage.md`](docs/dsl-coverage.md) lists what the DSL reaches.
- nftables 1.1.6 rejects `ct count` objects and references, so no live test exercises them. The corpus check covers their statement shapes only with a pin that carries nftables 1.1.7.
- Text output cannot represent every value that JSON can; [`docs/text-coverage.md`](docs/text-coverage.md) records the gaps.
- The compatibility helpers check only the static tables. They do not inspect kernel versions, modules, devices, or runtime state, so an `inet` or `netdev` ingress chain that `validChainPlacement` accepts can still require `dev`.

[Unreleased]: https://github.com/petohorvath/nix-nftypes/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petohorvath/nix-nftypes/releases/tag/v0.1.0
