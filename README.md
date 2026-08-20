# nix-nft-types

Strict Nix types, an ergonomic DSL, and pure renderers for nftables rulesets.
The library models libnftables JSON, catches many errors during Nix evaluation,
and can emit either JSON or nftables text.

The **JSON path is the compatibility target**. The text renderer covers the
common path and has separate live-parser and equivalence tests, but nftables'
text grammar cannot represent every JSON-valid value.

## Quick start

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.nix-nft-types.url = "github:petohorvath/nix-nftypes";

  outputs = { nixpkgs, nix-nft-types, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      nftlib = nix-nft-types.lib;
      inherit (nftlib.dsl) ruleset flush table eq inSet accept limit;
      inherit (nftlib.dsl.fields) tcp ct;
    in {
      packages.${system}.rules = pkgs.writeText "rules.json" (
        nftlib.toJson (ruleset [
          flush
          (table "inet" "filter" {
            chains.input = {
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "drop";
              rules = [
                [ (inSet ct.state [ "established" "related" ]) accept ]
                [
                  (eq tcp.dport 22)
                  (limit { rate = 10; per = "minute"; burst = 5; })
                  accept
                ]
              ];
            };
          })
        ])
      );
    };
}
```

Build and load the result:

```console
nix build .#rules
sudo nft -j -f result
```

See [`examples/basic-firewall-dsl.nix`](examples/basic-firewall-dsl.nix) for a
small complete ruleset and
[`examples/home-router-dsl.nix`](examples/home-router-dsl.nix) for a broader
showcase.

### Embed one table in NixOS

`toTextBlockPretty` emits the table contents expected by the NixOS nftables
module; NixOS supplies the outer table wrapper:

```nix
networking.nftables = {
  enable = true;
  tables.filter = {
    family = "inet";
    content = nftlib.toTextBlockPretty (
      nftlib.dsl.table "inet" "filter" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "drop";
          rules = [ [ nftlib.dsl.accept ] ];
        };
      }
    );
  };
};
```

## How it is structured

### 1. Schema

`nftlib.types` contains Nix module types for expressions, statements, objects,
commands, and complete rulesets. Primitive enums are also available as plain
lists under `nftlib.enums`.

Use the schema when accepting hand-written attrsets from another module. The
renderers are serializers; they do **not** automatically type-check arbitrary
raw values.

### 2. DSL

`nftlib.dsl` builds schema-shaped values with:

- field leaves such as `fields.tcp.dport`, `fields.ip.saddr`, and
  `fields.ct.state`;
- operators such as `eq`, `inSet`, and `within`;
- statement constructors such as `counter`, `log`, `limit`, `dnat`, and
  `reject`;
- a declarative `table` tree with named objects, chains, and ordered rules;
- command builders under `create`, `delete`, `destroy`, `list`, `reset`,
  `replace`, `insert`, and `rename`.

Table trees validate each assembled object, chain, and rule while expanding to
flat nftables commands. Unknown table-tree keys are rejected instead of being
silently ignored. `create.rule` is intentionally absent because nftables rejects
that command; use `dsl.rule` or a table tree's `rules` list.

Raw command attrsets may be mixed into `dsl.ruleset`, but those raw children are
passed through unchanged. Validate them with `nftlib.types.ruleset` when they
come from untrusted or user-authored configuration.

### 3. Renderers

| Function | Output | Intended consumer |
| --- | --- | --- |
| `toJson` | compact libnftables JSON | `nft -j -f` |
| `toNix` | pretty Nix syntax for inspection | humans; **not** `nft` |
| `toText` | compact imperative nftables text | `nft -f` |
| `toTextPretty` | multi-line imperative nftables text | `nft -f` |
| `toTextBlock` | compact contents of one table block | a host-supplied `table { ... }` wrapper |
| `toTextBlockPretty` | multi-line contents of one table block | a host-supplied `table { ... }` wrapper |

All renderers are pure Nix functions and do not invoke `nft`.
`toTextBlock*` accepts one `dsl.table` node, omits the table wrapper, and folds
rules into their parent chain. It is suitable for consumers such as
`networking.nftables.tables.<name>.content`. Because table-block grammar cannot
represent a standalone `element` command, block rendering rejects top-level
`elements.<name>` entries; place initial elements inside the corresponding set
or map definition instead.

## Public API

| Namespace | Purpose |
| --- | --- |
| `nftlib.types` | schema types and restricted-tag helpers |
| `nftlib.enums` | primitive enum values as lists |
| `nftlib.dsl` | fields, expressions, statements, objects, and commands |
| `nftlib.compatibility` | family/hook/chain-type and priority reference tables |
| `resolvePriority`, `priorityNameOf` | family-aware priority conversion |
| `chainTypeFor` | project policy classification from family/hook/priority |
| `validChainPlacement` | static family/type/hook matrix check |
| `cleanValue` | remove module markers and unset nullable fields before rendering |

The compatibility helpers check only their documented static dimensions. They
do not replace kernel-version, device, module, or runtime validation.

See [`docs/api.md`](docs/api.md) for the API details and validation examples.

## Compatibility and scope

The schema follows the parser and serializer shipped by the locked stable and
unstable nixpkgs inputs, including downstream nftables patches. It is not a
claim that every nftables feature, parser condition, read-back form, or text
spelling is modelled exactly.

Known differences are explicit and tested:

- the upstream statement corpus currently has 11 baselined divergence
  categories;
- some parser-conditional constraints are represented more permissively in
  Nix;
- plural `list`/`reset` command-selector forms and several slim selectors are
  not modelled;
- the text grammar has values and environment-dependent cases that the JSON
  path can handle but the text integration suite excludes.

See:

- [`docs/spec-coverage.md`](docs/spec-coverage.md) — schema versus parser and
  serializer;
- [`docs/dsl-coverage.md`](docs/dsl-coverage.md) — DSL reachability and
  validation boundaries;
- [`docs/text-coverage.md`](docs/text-coverage.md) — text-renderer evidence and
  limitations;
- [`docs/upstream-sync.md`](docs/upstream-sync.md) — locked checks and the
  weekly channel-tip canary.

## Verification

Checks and source packages are exposed on `x86_64-linux` and `aarch64-linux`.
The library is platform-independent, and the formatter is also exposed on both
Darwin systems. GitHub CI builds every `x86_64-linux` check.

Run each check system on a matching native builder. Source-derived checks use
import-from-derivation, so `nix flake check --all-systems` from one architecture
is not a cross-architecture verification command.

```console
nix fmt -- --ci
nix flake check
```

For the exact check list:

```console
nix eval --json '.#checks.x86_64-linux' --apply builtins.attrNames | jq .
```

Each channel-dependent check is instantiated against both locked inputs:
plain names use stable `nixpkgs`, and `-unstable` names use
`nixpkgs-unstable`. The matrix includes Nix-level schema/DSL tests, JSON and
text parser tests in private network namespaces, selected JSON/text semantic
equivalence cases, safety regressions, source provenance, upstream corpus and
enum extraction, read-back validation, and tooling self-tests.

A scheduled Monday canary repeats the nine nftables-facing checks against an
immutable snapshot of each channel's current tip. It is deliberately
non-gating and does not modify `flake.lock`.

## Repository layout

```text
lib/schema/   schema types
lib/dsl/      ergonomic constructors and table-tree expansion
lib/json/     JSON and diagnostic Nix rendering
lib/text/     nftables text rendering
examples/     raw and DSL examples
tests/        unit, live-parser, safety, and upstream-drift checks
tooling/      corpus and source-analysis helpers
docs/         API and coverage notes
```
