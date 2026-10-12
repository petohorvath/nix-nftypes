/*
  Package-set-dependent tests, instantiated from `nixpkgs`.
  Every test runs nix-unit with the package set's `lib` and `nix-unit`.
  The live tests first run probes against the package set's `nft` binary
  or the source tooling and record what happened; their suites assert on
  those records. The project policy's stable and unstable pin runs make
  this the "compatible with stable AND unstable" contract.

  Returns the checks by name. The live-parser tests are VM tests because
  their probes run in a NixOS VM (./vm.nix). Each declares the VM's system
  features, so the project policy builds it only on a runner that has them.
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
    `nft -c -j -f` (plus parser-negative cases), both block forms through
    `nft -c -f`, JSON vs text real loads whose `nft list ruleset` must
    agree, `nft -c -f` for the pretty text those real loads cannot cover,
    real-load read-backs of safe comments and ifname sets, and real-load
    round trips.
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

  # Source-side tests use the exact release archive and downstream
  # patches carried by this package set's nftables derivation. They cover
  # valid shapes the hand-written integration cases cannot anticipate.
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
    requiredSystemFeatures: name: test:
    let
      testObservationPaths = lib.getAttrs (test.probes or [ test.suite ]) observationPaths;
    in
    nixUnitCheck {
      inherit name requiredSystemFeatures;
      entryPoint = "live.nix";
      suites = [ test.suite ];
      observationPaths = testObservationPaths;
      summary = (summaries.${name} or (_: "")) testObservationPaths;
    };
in
{
  # Every evaluation-only suite: schema and DSL behaviour, text parity,
  # safety regressions, validation messages, and the nixpkgs-source policy.
  unit-tests = nixUnitCheck {
    name = "unit-tests";
    entryPoint = "unit.nix";
  };
}
// lib.mapAttrs (liveTest [ ]) sourceTests
# The NixOS VM run of their probes requires these features.
// lib.mapAttrs (liveTest [
  "kvm"
  "nixos-test"
]) liveParserTests
