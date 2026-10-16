/*
  nix-unit entry point for the integration suites, which assert on what
  the probes (../helpers/probes) recorded from the package set's `nft` and
  the source tooling. Groups each suite's tests under the suite's file
  name.

  `observationPaths` maps each observation name to its probe record; only
  the selected suites' records need to be present. Each suite runs as its
  own `integration-<suite>` entry (../default.nix), which passes the
  records it reads.
*/
{
  nixpkgs,
  observationPaths,
  system,
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
