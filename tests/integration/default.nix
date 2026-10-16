/*
  nix-unit entry point for the integration suites, which assert on what
  the probes (../helpers/probes) recorded from the package set's `nft` and
  the source tooling. Groups each suite's tests under the suite's file
  name.

  Run locally with `nix-unit tests/integration --attr <suite>`, which
  builds the probes the suite reads; the `nft` probes run in a NixOS VM,
  which needs KVM.
*/
let
  rootInputs = (builtins.getFlake (toString ../..)).inputs;
in
{
  nixpkgs ? rootInputs.nixpkgs,
  system ? builtins.currentSystem,
  /*
    Each observation's probe record, by observation name; only the
    selected suites' records need to be present. tests/default.nix passes
    the records of the flake's package set, and a local run builds them
    here.
  */
  observationPaths ?
    let
      pkgs = nixpkgs.legacyPackages.${system};
      probeContext = import ../test-context.nix { inherit nixpkgs system; };
    in
    import ../helpers/probes {
      inherit pkgs;
      inherit (probeContext) fixtures nftlib;
      nftablesSource = (import ../../packages { inherit pkgs; }).nftables-source;
    },
}:
let
  testContext = import ../test-context.nix {
    inherit nixpkgs observationPaths system;
  };
in
{
  chain-placement = import ./chain-placement.nix testContext;
  comment-safety = import ./comment-safety.nix testContext;
  dsl = import ./dsl.nix testContext;
  ifname-safety = import ./ifname-safety.nix testContext;
  nft-misbehaviour = import ./nft-misbehaviour.nix testContext;
  nftables-corpus = import ./nftables-corpus.nix testContext;
  nftables-enum-extraction = import ./nftables-enum-extraction.nix testContext;
  nftables-roundtrip = import ./nftables-roundtrip.nix testContext;
  nftables-source-provenance = import ./nftables-source-provenance.nix testContext;
  nftables-tooling-selftest = import ./nftables-tooling-selftest.nix testContext;
  parse-check = import ./parse-check.nix testContext;
  render-equivalence = import ./render-equivalence.nix testContext;
  text-block = import ./text-block.nix testContext;
}
