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
  tagsOf = import ./helpers/tags-of.nix;
  helpers = import ./helpers { inherit lib nftlib; };

  nftSafeIfname = import ../lib/nft-safe-ifname.nix { };
  nftSafeScalar = import ../lib/nft-safe-scalar.nix { };
  nftSafeString = import ../lib/nft-safe-string.nix { };
  # The text module itself, so drift checks read the exact dispatch tables
  # the production renderers use.
  clean = import ../lib/clean.nix { inherit lib; };
  text = import ../lib/text {
    inherit
      clean
      lib
      nftSafeIfname
      nftSafeScalar
      nftSafeString
      ;
    nftSafeLogPrefix = import ../lib/nft-safe-log-prefix.nix { inherit nftSafeString; };
    prepareRuleset = import ../lib/prepare-ruleset.nix {
      inherit clean lib;
      rulesetEntry = import ../lib/ruleset-entry.nix {
        inherit lib;
        readBackTags = tagsOf nftlib.types.readBackObject;
        verbs = tagsOf nftlib.types.command;
      };
    };
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
      # The payload fields nft loads as written, which the Field leaves
      # cover.
      payloadFieldsByProtocol = import ../lib/schema/payload-fields.nix { };
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
