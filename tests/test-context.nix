# Builds `testContext`, the single argument every nix-unit suite receives.
# `observationPaths` maps each observation name to the probe record that
# the integration suites assert on; the unit entry point passes none.
{
  nixpkgs,
  observationPaths ? null,
}:
let
  inherit (nixpkgs) lib;
  nftlib = import ../lib { inherit lib; };
  helpers = import ./helpers { inherit lib nftlib; };

  nftSafeIfname = import ../lib/nft-safe-ifname.nix { };
  nftSafeScalar = import ../lib/nft-safe-scalar.nix { };
  nftSafeString = import ../lib/nft-safe-string.nix { };
  # The text module itself, so drift checks read the exact dispatch tables
  # the production renderers use.
  text = import ../lib/text {
    inherit
      lib
      nftSafeIfname
      nftSafeScalar
      nftSafeString
      ;
    nftSafeLogPrefix = import ../lib/nft-safe-log-prefix.nix { inherit nftSafeString; };
    clean = import ../lib/clean.nix { inherit lib; };
  };

  testContext = {
    inherit helpers lib nftlib;
    # Modules that `nftlib` does not export, exercised directly so
    # defence-in-depth checks are pinned independently of the public API.
    internal = {
      inherit nftSafeIfname nftSafeScalar;
      dslMergeDisjoint = import ../lib/dsl/internal/merge-disjoint.nix { inherit lib; };
      # The object-kind registry, so a test covers every kind a table tree
      # holds without repeating the registry.
      dslObjectKinds = import ../lib/dsl/structure/object-kinds.nix {
        inherit lib;
        objects = nftlib.types.objectBodies;
      };
      textBlockFields = text.blockFields;
      textDispatch = text.dispatch;
      textPrimitives = text.primitives;
    };
    observations =
      if observationPaths == null then
        { }
      else
        lib.mapAttrs (_: path: builtins.fromJSON (builtins.readFile path)) observationPaths;
    fixtures = import ./fixtures {
      inherit lib nftlib;
      # The parity suites whose expected values the parse check sends to
      # nft.
      paritySuites = {
        dslParity = import ./unit/dsl-parity.nix testContext;
        textBlockParity = import ./unit/text-block-parity.nix testContext;
        textParity = import ./unit/text-parity.nix testContext;
      };
    };
  };
in
testContext
