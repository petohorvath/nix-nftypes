# nix-nftypes

nix-nftypes is a Nix library of strict types, a DSL, and pure renderers for nftables rulesets, checked against the nftables that nixpkgs packages. NixOS modules and flakes use it to build firewall rulesets as Nix values, catch many mistakes during evaluation, and emit libnftables JSON or nftables text.

## Overview

The library has three layers:

- **Schema** (`nftlib.types`): Nix module types that model libnftables JSON, from primitive enums up to a complete ruleset. `nftlib.validate` checks a hand-written attrset against them.
- **DSL** (`nftlib.dsl`): constructors that build the same schema-shaped values with less repetition. It provides field leaves such as `fields.tcp.dport`, operators such as `eq` and `inSet`, statements such as `counter`, `limit`, and `dnat`, command builders, and a declarative table tree of named objects, chains, and ordered rules.
- **Renderers** (`toJson`, `toText`, and others): pure functions that turn a value into libnftables JSON or nftables text without calling `nft`.

JSON is the compatibility target. The text renderers cover the common path and have their own live-parser tests, but the nftables text grammar cannot represent every value that JSON can.

## Install

Add the flake as an input and take the library from its system-independent `lib` output:

```nix
inputs.nix-nftypes.url = "github:petohorvath/nix-nftypes";
```

To pin a release, append its tag to the URL: `github:petohorvath/nix-nftypes/v0.1.0`.

## Usage

This flake renders a ruleset with one input chain as nftables text:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.nix-nftypes.url = "github:petohorvath/nix-nftypes";

  outputs = { nixpkgs, nix-nftypes, ... }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      nftlib = nix-nftypes.lib;
      inherit (nftlib.dsl) accept eq flush inSet ruleset table;
      inherit (nftlib.dsl.fields) ct tcp;
    in
    {
      packages.x86_64-linux.rules = pkgs.writeText "rules.nft" (
        nftlib.toTextPretty (ruleset [
          (flush.ruleset { })
          (table "inet" "filter" {
            chains.input = {
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "drop";
              rules = [
                [ (inSet ct.state [ "established" "related" ]) accept ]
                [ (eq tcp.dport 22) accept ]
              ];
            };
          })
        ])
      );
    };
}
```

```console
$ nix build .#rules && cat result
flush ruleset
add table inet filter
add chain inet filter input {
  type filter hook input priority 0;
  policy drop;
}
add rule inet filter input ct state == { established, related } accept
add rule inet filter input tcp dport == 22 accept
```

Load the text with `sudo nft -f result`. To produce libnftables JSON, the compatibility target, render with `nftlib.toJson` instead and load the result with `sudo nft -j -f result`.

The [`examples`](examples) directory holds longer rulesets, each a function of `nftlib`:

- [`basic-firewall-dsl.nix`](examples/basic-firewall-dsl.nix): a small firewall with sets, maps, NAT, logging, and rate limits.
- [`basic-firewall.nix`](examples/basic-firewall.nix): a similar firewall written as raw attrsets.
- [`home-router-dsl.nix`](examples/home-router-dsl.nix): a broader showcase of the DSL.

## Choose a renderer

| Renderer | Output | Consumer |
| --- | --- | --- |
| `toJson` | compact libnftables JSON | `nft -j -f` |
| `toText` | compact imperative nftables text | `nft -f` |
| `toTextPretty` | multi-line imperative nftables text | `nft -f` |
| `toTextBlock` | compact block form of one table | a host that supplies the `table { … }` wrapper |
| `toTextBlockPretty` | multi-line block form of one table | a host that supplies the `table { … }` wrapper |
| `toNix` | Nix syntax for inspection | people, not `nft` |

[`docs/api.md`](docs/api.md) documents every renderer, the schema types, the DSL, and the compatibility helpers. [`GLOSSARY.md`](GLOSSARY.md) defines the project's terms.

## Embed a table in NixOS

`toTextBlockPretty` renders one `dsl.table` as block form: the table's contents, including its `flags` and `comment`, without the `table { … }` wrapper, with each rule inside its chain. The NixOS nftables module takes this form in `networking.nftables.tables.<name>.content` and supplies the wrapper:

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

Block form has no standalone `element` command, so it rejects a table tree with top-level `elements.<name>` entries. Put initial elements on the set or map definition instead.

## Validate hand-written rulesets

The DSL validates every object, chain, and rule it assembles when output is requested. The renderers do not validate: they clean and render whatever they receive. A raw attrset, whether rendered directly or passed among the commands of `dsl.ruleset`, reaches the output unchecked.

Validate raw values that come from users or other modules with `nftlib.validate`, before rendering them:

```nix
nftlib.toJson (nftlib.validate nftlib.types.ruleset raw)
```

[`docs/api.md`](docs/api.md#validation-model) describes what it returns and how it reports a mismatch.

## Limitations

- The schema follows the patched nftables that nixpkgs ships on its stable and unstable branches, not upstream nftables. It has known differences from that parser, such as parser conditions left to `nft` and command selectors it does not model; [`docs/spec-coverage.md`](docs/spec-coverage.md) lists them, and [`docs/dsl-coverage.md`](docs/dsl-coverage.md) lists what the DSL reaches.
- Text output cannot represent every value that JSON can, and some cases depend on the environment; [`docs/text-coverage.md`](docs/text-coverage.md) records the evidence and gaps.
- The compatibility helpers, such as `validChainPlacement`, check only static family, chain-type, hook, and priority tables. They do not inspect kernel versions, modules, devices, or runtime state.

## Contributing

Report bugs and ask questions in [GitHub Issues](https://github.com/petohorvath/nix-nftypes/issues). [AGENTS.md](AGENTS.md) lists the required checks, and [`docs/upstream-sync.md`](docs/upstream-sync.md) describes the test matrix.

## License

MIT. See [`LICENSE`](LICENSE).
