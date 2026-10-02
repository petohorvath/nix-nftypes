/*
  Package-set-dependent check set, instantiated once per nixpkgs flake
  input. Everything here depends on the package set through one of two
  surfaces: the nix-unit suites exercise the package set's `lib` (module
  system, error-message shapes, which can shift between nixpkgs releases)
  and `nix-unit`, and the live-parser checks exercise the package set's
  `nft` binary. Running the set against both package sets is the
  "compatible with stable AND unstable" contract, enforced on every
  `nix flake check`.
*/
{ pkgs, nftablesSource }:
let
  helpers = import ./helpers { inherit (pkgs) lib; };
  inherit (helpers) nftlib;
  fixtures = import ./fixtures { inherit (nftlib) dsl; };
  integration = import ./checks/dsl-integration.nix {
    inherit (pkgs) lib;
    inherit nftlib;
  };
  textIntegration = import ./checks/text-integration.nix {
    inherit (pkgs) lib;
    inherit nftlib;
  };
  renderEquivalence = import ./checks/render-equivalence.nix {
    inherit (pkgs) lib;
    inherit nftlib;
  };
  sourceProvenance = import ./checks/nftables-source-provenance.nix {
    inherit nftablesSource pkgs;
  };
  nftablesCorpus = import ./checks/upstream-corpus.nix {
    inherit helpers nftablesSource pkgs;
  };
  nftablesEnums = import ./checks/upstream-enums.nix {
    inherit nftablesSource nftlib pkgs;
  };
  nftablesRoundtrip = import ./checks/upstream-roundtrip.nix {
    inherit helpers pkgs;
    nftables = pkgs.nftables;
  };
  nftablesSelftest = import ./checks/upstream-selftest.nix {
    inherit helpers nftablesSource pkgs;
  };
in
{
  # Every eval-time suite: schema and DSL behaviour, text parity, safety
  # regressions, validation messages, and the nixpkgs-source policy.
  unit-tests = import ./unit-tests.nix { inherit pkgs; };
  # End-to-end: each case is rendered and piped through
  # `unshare -rn nft -c -j -f` (the real libnftables parser inside a
  # private network namespace). Catches any divergence between the
  # DSL's JSON output and what nftables actually accepts.
  integration-tests = integration.runIntegrationTests pkgs integration.cases;
  # Block-form text-renderer live-parser check: each case is
  # rendered via toTextBlockPretty and toTextBlock, wrapped in
  # `table <fam> <name> { ... }`, and piped through
  # `unshare -rn nft -c -f -` to verify the round-trip is
  # accepted by the upstream parser.
  text-block-integration-tests = import ./checks/text-block-integration.nix {
    inherit fixtures nftlib pkgs;
  };
  # Text-renderer live-parser tests: same case set as
  # integration-tests, but rendered to text and piped through
  # `unshare -rn nft -c -f -` (no `-j`).
  text-integration-tests = textIntegration.runIntegrationTests pkgs textIntegration.textCases;
  # Render-equivalence: render each case via JSON and via text,
  # load both into separate netns, diff `nft list ruleset`. The
  # binding 1:1 contract — both renderers agree on what they
  # build inside the kernel.
  render-equivalence-tests = renderEquivalence.runEquivalenceTests pkgs renderEquivalence.equivalenceCases;
  # Safe comments round-trip byte-for-byte through the text and JSON
  # load paths.
  comment-safety-integration-tests = import ./checks/comment-safety-integration.nix {
    inherit fixtures nftlib pkgs;
  };
  # Safe ifname sets keep their element count through the text and
  # JSON load paths, so bare-comma widening cannot return unnoticed.
  ifname-safety-integration-tests = import ./checks/ifname-safety-integration.nix {
    inherit fixtures nftlib pkgs;
  };

  # Source-side compatibility checks use the exact release archive and
  # downstream patches carried by this package set's nftables
  # derivation. They complement the live binary checks above by
  # covering valid shapes the hand-written integration corpus cannot
  # anticipate.
  nftables-source-provenance-tests = sourceProvenance.runTests pkgs;
  nftables-corpus-tests = nftablesCorpus.runTests pkgs;
  nftables-enum-extraction-tests = nftablesEnums.runTests pkgs;
  nftables-roundtrip-tests = nftablesRoundtrip.runTests pkgs;
  nftables-tooling-selftests = nftablesSelftest.runTests pkgs;
}
