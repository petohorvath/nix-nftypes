/*
  Builds `testContext`, the single argument every suite receives.
  `observations` holds the parsed probe records the live suites assert on.
*/
{
  lib,
  observations ? { },
}:
let
  helpers = import ./helpers { inherit lib; };
  testContext = {
    inherit helpers lib observations;
    inherit (helpers) nftlib;
    fixtures = import ./fixtures {
      inherit lib;
      inherit (helpers) exampleChildren examples nftlib;
      # The parity suites whose expected values the parse check sends to
      # nft.
      paritySuites = {
        dslParity = import ./suites/dsl-parity.nix testContext;
        textBlockParity = import ./suites/text-block-parity.nix testContext;
        textParity = import ./suites/text-parity.nix testContext;
      };
    };
  };
in
testContext
