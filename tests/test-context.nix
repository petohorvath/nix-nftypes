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
  testContext = {
    inherit helpers lib nftlib;
    # A record read through a path with context, as a local run's built
    # records are, carries the store paths it names as context, which
    # nix-unit refuses in a test's values; the sandbox reads path literals.
    observations =
      if observationPaths == null then
        { }
      else
        lib.mapAttrs (
          _: path: builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.readFile path))
        ) observationPaths;
    fixtures = import ./fixtures {
      inherit lib nftlib;
      inherit (helpers) exampleChildren examples;
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
