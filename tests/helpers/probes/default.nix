/*
  Every probe record for one package set, by the observation name the
  integration suites read it under: the source records, built in the
  sandbox, and the `nft` records, which the runners (./nft.nix) write in
  one NixOS VM run (./vm.nix).
*/
{
  fixtures,
  nftablesSource,
  nftlib,
  pkgs,
}:
let
  inherit (pkgs) lib;
  inherit (pkgs.callPackage ./record-runs.nix { }) writeRunner recordRuns;
  nftRunners = import ./nft.nix {
    inherit
      fixtures
      writeRunner
      nftlib
      pkgs
      ;
  };
  vmRun = import ./vm.nix {
    inherit pkgs;
    runners = nftRunners;
  };
in
import ./source.nix {
  inherit
    nftablesSource
    pkgs
    recordRuns
    ;
}
// lib.mapAttrs (name: _: "${vmRun}/probes/${name}.json") nftRunners
