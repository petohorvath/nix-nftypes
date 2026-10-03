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
in
{
  inherit helpers lib observations;
  inherit (helpers) nftlib;
  fixtures = import ./fixtures {
    inherit (helpers) examples;
    inherit (helpers.nftlib) dsl;
  };
}
