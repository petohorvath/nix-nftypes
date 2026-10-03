/*
  Package-set-dependent check set, instantiated once per nixpkgs flake
  input. Every check runs nix-unit with the package set's `lib` and
  `nix-unit`. The live checks first build probes that run the package
  set's `nft` binary or the source tooling and record what happened; their
  suites assert on those records. Running the set against both package
  sets is the "compatible with stable AND unstable" contract, enforced on
  every `nix flake check`.
*/
{ pkgs, nftablesSource }:
let
  inherit (pkgs) lib;
  testContext = import ./context.nix { inherit lib; };
  probes = import ./probes {
    inherit nftablesSource pkgs;
    inherit (testContext) fixtures nftlib;
  };
  nixUnitCheck = import ./nix-unit-check.nix { inherit pkgs; };
  summaries = import ./summaries.nix {
    inherit pkgs;
    inherit (testContext) fixtures;
  };

  /*
    Live checks by name: each runs one suite from ./live.nix against the
    named probes' records. Most suites read the probe of the same name.

    Live parsers run inside a private network namespace: JSON through
    `nft -c -j -f` (plus parser-negative cases), both block forms through
    `nft -c -f`, JSON vs text real loads whose `nft list ruleset` must
    agree, `nft -c -f` for the pretty text those real loads cannot cover,
    and real-load read-backs of safe comments and ifname sets.

    Source-side checks use the exact release archive and downstream
    patches carried by this package set's nftables derivation. They cover
    valid shapes the hand-written integration cases cannot anticipate.
  */
  liveChecks = {
    integration-tests.suite = "dslIntegration";
    text-integration-tests.suite = "textIntegration";
    text-block-integration-tests.suite = "textBlockIntegration";
    render-equivalence-tests.suite = "renderEquivalence";
    comment-safety-integration-tests.suite = "commentSafetyIntegration";
    ifname-safety-integration-tests.suite = "ifnameSafetyIntegration";
    nftables-source-provenance-tests = {
      suite = "nftablesSourceProvenance";
      probes = [
        "nftablesSourceProvenance"
        "nftablesSourceTree"
      ];
    };
    nftables-corpus-tests.suite = "nftablesCorpus";
    nftables-enum-extraction-tests.suite = "nftablesEnumExtraction";
    nftables-roundtrip-tests.suite = "nftablesRoundtrip";
    nftables-tooling-selftests = {
      suite = "nftablesToolingSelftest";
      probes = [
        "nftablesToolingSelftest"
        "nftablesToolingSelftestCorpus"
      ];
    };
  };
in
{
  # Every evaluation-only suite: schema and DSL behaviour, text parity,
  # safety regressions, validation messages, and the nixpkgs-source
  # policy.
  unit-tests = nixUnitCheck {
    name = "unit-tests";
    entryPoint = "unit.nix";
  };
}
// lib.mapAttrs (
  name: check:
  let
    observationPaths = lib.getAttrs (check.probes or [ check.suite ]) probes;
  in
  nixUnitCheck {
    inherit name observationPaths;
    entryPoint = "live.nix";
    suites = [ check.suite ];
    summary = (summaries.${name} or (_: "")) observationPaths;
  }
) liveChecks
