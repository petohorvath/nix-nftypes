/*
  nix-unit entry point for the live suites, which assert on what the
  probes (./probes) recorded from the package set's `nft` and the source
  tooling. `observationPaths` maps each suite's probe name to the probe's
  JSON output; only the selected suites' probes need to be present.
*/
{ lib, observationPaths }:
let
  testContext = import ./context.nix {
    inherit lib;
    observations = lib.mapAttrs (_: path: builtins.fromJSON (builtins.readFile path)) observationPaths;
  };
in
{
  commentSafetyIntegration = import ./suites/comment-safety-integration.nix testContext;
  dslIntegration = import ./suites/dsl-integration.nix testContext;
  ifnameSafetyIntegration = import ./suites/ifname-safety-integration.nix testContext;
  nftablesCorpus = import ./suites/nftables-corpus.nix testContext;
  nftablesEnumExtraction = import ./suites/nftables-enum-extraction.nix testContext;
  nftablesRoundtrip = import ./suites/nftables-roundtrip.nix testContext;
  nftablesSourceProvenance = import ./suites/nftables-source-provenance.nix testContext;
  nftablesToolingSelftest = import ./suites/nftables-tooling-selftest.nix testContext;
  renderEquivalence = import ./suites/render-equivalence.nix testContext;
  textBlockIntegration = import ./suites/text-block-integration.nix testContext;
  textIntegration = import ./suites/text-integration.nix testContext;
}
