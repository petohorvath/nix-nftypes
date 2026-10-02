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
  helpers = import ./helpers { inherit lib; };
  probes = import ./probes {
    inherit nftablesSource pkgs;
    inherit (helpers) nftlib;
    fixtures = import ./fixtures {
      inherit (helpers) examples;
      inherit (helpers.nftlib) dsl;
    };
  };
  nixUnitCheck = import ./nix-unit-check.nix { inherit pkgs; };

  # A check running one live suite against the named probes' records.
  liveCheck =
    name: suite: probeNames:
    nixUnitCheck {
      inherit name;
      entryPoint = "live.nix";
      suites = [ suite ];
      observationPaths = lib.getAttrs probeNames probes;
    };
  # Most live suites read the probe of the same name.
  liveCheckOf = name: suite: liveCheck name suite [ suite ];
in
{
  # Every evaluation-only suite: schema and DSL behaviour, text parity,
  # safety regressions, validation messages, and the nixpkgs-source
  # policy.
  unit-tests = nixUnitCheck {
    name = "unit-tests";
    entryPoint = "unit.nix";
  };

  # Live parsers, each inside a private network namespace: JSON through
  # `nft -c -j -f` (plus parser-negative cases), pretty text and both
  # block forms through `nft -c -f`, and JSON vs text real loads whose
  # `nft list ruleset` must agree.
  integration-tests = liveCheckOf "integration-tests" "dslIntegration";
  text-integration-tests = liveCheckOf "text-integration-tests" "textIntegration";
  text-block-integration-tests = liveCheckOf "text-block-integration-tests" "textBlockIntegration";
  render-equivalence-tests = liveCheckOf "render-equivalence-tests" "renderEquivalence";
  # Safe comments and ifname sets survive a real load and read-back.
  comment-safety-integration-tests = liveCheckOf "comment-safety-integration-tests" "commentSafetyIntegration";
  ifname-safety-integration-tests = liveCheckOf "ifname-safety-integration-tests" "ifnameSafetyIntegration";

  # Source-side compatibility checks use the exact release archive and
  # downstream patches carried by this package set's nftables
  # derivation. They complement the live binary checks above by
  # covering valid shapes the hand-written integration cases cannot
  # anticipate.
  nftables-source-provenance-tests =
    liveCheck "nftables-source-provenance-tests" "nftablesSourceProvenance"
      [
        "nftablesSourceProvenance"
        "nftablesSourceTree"
      ];
  nftables-corpus-tests = liveCheckOf "nftables-corpus-tests" "nftablesCorpus";
  nftables-enum-extraction-tests = liveCheckOf "nftables-enum-extraction-tests" "nftablesEnumExtraction";
  nftables-roundtrip-tests = liveCheckOf "nftables-roundtrip-tests" "nftablesRoundtrip";
  nftables-tooling-selftests = liveCheck "nftables-tooling-selftests" "nftablesToolingSelftest" [
    "nftablesToolingSelftest"
    "nftablesToolingSelftestCorpus"
  ];
}
