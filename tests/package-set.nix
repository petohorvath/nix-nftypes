/*
  Package-set-dependent tests, instantiated once per nixpkgs flake input.
  Every test runs nix-unit with the package set's `lib` and `nix-unit`.
  The live tests first run probes against the package set's `nft` binary
  or the source tooling and record what happened; their suites assert on
  those records. Running the set against both package sets is the
  "compatible with stable AND unstable" contract.

  Returns `{ checks; vmTests; }`. The live-parser tests are VM tests
  because their probes run in a NixOS VM (./vm.nix); everything else is a
  check.
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

  vmRun = import ./vm.nix {
    inherit pkgs;
    runners = probes.nft;
  };
  observationPaths =
    probes.source // lib.mapAttrs (name: _: "${vmRun}/probes/${name}.json") probes.nft;

  /*
    Live tests by name: each runs one suite from ./live.nix against the
    named probes' records. Most suites read the probe of the same name.

    Live parsers run inside a private network namespace: JSON through
    `nft -c -j -f` (plus parser-negative cases), pretty text and both
    block forms through `nft -c -f`, JSON vs text real loads whose
    `nft list ruleset` must agree, real-load read-backs of safe comments
    and ifname sets, and real-load round trips.
  */
  liveParserTests = {
    integration-tests.suite = "dslIntegration";
    text-integration-tests.suite = "textIntegration";
    text-block-integration-tests.suite = "textBlockIntegration";
    render-equivalence-tests.suite = "renderEquivalence";
    comment-safety-integration-tests.suite = "commentSafetyIntegration";
    ifname-safety-integration-tests.suite = "ifnameSafetyIntegration";
    nftables-roundtrip-tests.suite = "nftablesRoundtrip";
  };

  /*
    Source-side tests use the exact release archive and downstream
    patches carried by this package set's nftables derivation. They cover
    valid shapes the hand-written integration cases cannot anticipate.
  */
  sourceTests = {
    nftables-source-provenance-tests = {
      suite = "nftablesSourceProvenance";
      probes = [
        "nftablesSourceProvenance"
        "nftablesSourceTree"
      ];
    };
    nftables-corpus-tests.suite = "nftablesCorpus";
    nftables-enum-extraction-tests.suite = "nftablesEnumExtraction";
    nftables-tooling-selftests = {
      suite = "nftablesToolingSelftest";
      probes = [
        "nftablesToolingSelftest"
        "nftablesToolingSelftestCorpus"
      ];
    };
  };

  liveTest =
    name: test:
    nixUnitCheck {
      inherit name;
      entryPoint = "live.nix";
      suites = [ test.suite ];
      observationPaths = lib.getAttrs (test.probes or [ test.suite ]) observationPaths;
    };
in
{
  checks = {
    # Every evaluation-only suite: schema and DSL behaviour, text parity,
    # safety regressions, validation messages, and the nixpkgs-source
    # policy.
    unit-tests = nixUnitCheck {
      name = "unit-tests";
      entryPoint = "unit.nix";
    };
  }
  // lib.mapAttrs liveTest sourceTests;

  vmTests = lib.mapAttrs liveTest liveParserTests;
}
