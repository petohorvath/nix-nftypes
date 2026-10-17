# The children each table-tree example passes to `dsl.ruleset`, which an
# Integration case needs for its block form: the example gets a
# `dsl.ruleset` that returns them as they are.
{ lib, nftlib }:
let
  childrenOf =
    path:
    import path {
      nftlib = nftlib // {
        dsl = nftlib.dsl // {
          ruleset = lib.id;
        };
      };
    };
in
{
  basicFirewallDsl = childrenOf ../../examples/basic-firewall-dsl.nix;
  homeRouterDsl = childrenOf ../../examples/home-router-dsl.nix;
}
