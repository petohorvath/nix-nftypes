/*
  Assembles the repo-specific `integration-<suite>` entries of the
  `checks` output for one package set, each reading the probe records of
  the package set's `nft` binary or of the patched source taken from the
  exported `nftables-source` package. The unit suites run in the
  `nix-unit` entry of nix-unit's flake-parts module (dev/default.nix).

  The project policy builds the entries again with its stable and
  unstable pins overriding `nixpkgs`, so a newer nftables (or `lib`
  module system) turns a test red instead of surfacing in a consumer's
  deployment.

  nftables has no independent flake input. Each compatibility surface uses
  the exact binary, release source, and downstream patches carried by the
  nixpkgs package set. This keeps the test oracle identical to what
  consumers install and avoids a second, fragile upstream-Git authority.
*/
{ inputs, pkgs }:
let
  inherit (pkgs) lib;
  integrationCheck = import ./helpers/integration-check.nix { inherit pkgs; };

  testContext = import ./test-context.nix { inherit (inputs) nixpkgs; };
  observationPaths = import ./helpers/probes {
    inherit pkgs;
    inherit (testContext) fixtures nftlib;
    nftablesSource = inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.nftables-source;
  };
  summaries = import ./helpers/summaries.nix { inherit pkgs; };

  /*
    The integration suites whose probes run the package set's `nft` in the
    NixOS VM run, with the observations each reads. The probes run inside
    a private network namespace: JSON through `nft -c -j -f` (plus
    parser-negative cases), both block forms through `nft -c -f`, real
    loads of JSON and each text form whose `nft list ruleset` must agree,
    real-load read-backs of safe comments and ifname sets, real-load round
    trips, "still misbehaves" cases, `nft -c` of every parity pin and
    Field leaf, a base chain at every family × chain type × hook
    placement, and a filter chain at every hook and priority symbol.
  */
  nftSuites = {
    chain-placement = [
      "chainPlacement"
      "prioritySymbols"
    ];
    comment-safety = [ "commentSafetyIntegration" ];
    dsl = [ "dslIntegration" ];
    ifname-safety = [ "ifnameSafetyIntegration" ];
    nft-misbehaviour = [ "nftMisbehaviour" ];
    nftables-roundtrip = [ "nftablesRoundtrip" ];
    parse-check = [ "parseCheck" ];
    render-equivalence = [ "renderEquivalence" ];
    text-block = [ "textBlockIntegration" ];
  };

  # The integration suites over the exact release archive and downstream
  # patches carried by this package set's nftables derivation. They cover
  # valid shapes the hand-written Integration cases cannot anticipate.
  sourceSuites = {
    nftables-corpus = [ "nftablesCorpus" ];
    nftables-enum-extraction = [ "nftablesEnumExtraction" ];
    nftables-source-provenance = [
      "nftablesSourceProvenance"
      "nftablesSourceTree"
    ];
    nftables-tooling-selftest = [
      "nftablesToolingSelftest"
      "nftablesToolingSelftestCorpus"
      "nftablesToolingSelftestProvenance"
    ];
  };

  integrationEntry =
    requiredSystemFeatures: suite: observations:
    let
      suiteObservationPaths = lib.getAttrs observations observationPaths;
    in
    lib.nameValuePair "integration-${suite}" (integrationCheck {
      inherit suite requiredSystemFeatures;
      observationPaths = suiteObservationPaths;
      postCheck = (summaries.${suite} or (_: "")) suiteObservationPaths;
    });
in
lib.attrsets.unionOfDisjoint (lib.mapAttrs' (integrationEntry [ ]) sourceSuites)
  # The NixOS VM run of their probes requires these features.
  (
    lib.mapAttrs' (integrationEntry [
      "kvm"
      "nixos-test"
    ]) nftSuites
  )
