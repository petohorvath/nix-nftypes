# Every probe for one package set, keyed by the observation name the live
# suites read it under: `source` holds records built in the sandbox, and
# `nft` holds runners for the VM tests.
{
  fixtures,
  nftablesSource,
  nftlib,
  pkgs,
}:
let
  inherit (pkgs.callPackage ./record-runs.nix { }) mkRunner recordRuns;
in
{
  nft = import ./nft.nix {
    inherit
      fixtures
      mkRunner
      nftlib
      pkgs
      ;
  };
  source = import ./source.nix {
    inherit
      nftablesSource
      nftlib
      pkgs
      recordRuns
      ;
  };
}
