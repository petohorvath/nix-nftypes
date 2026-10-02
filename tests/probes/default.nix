# Every probe for one package set, keyed by the live suite that reads it.
{
  fixtures,
  nftablesSource,
  nftlib,
  pkgs,
}:
let
  recordRuns = pkgs.callPackage ./record-runs.nix { };
in
import ./nft.nix {
  inherit
    fixtures
    nftlib
    pkgs
    recordRuns
    ;
}
// import ./source.nix {
  inherit
    nftablesSource
    nftlib
    pkgs
    recordRuns
    ;
}
