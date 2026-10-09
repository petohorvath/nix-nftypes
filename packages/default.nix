/*
  The patched source tree is exposed for the scheduled branch-tip comparison
  and for manual inspection. The matching binary remains the ordinary
  `pkgs.nftables` package.
*/
{ pkgs }:
{
  nftables-source = pkgs.callPackage ./nftables-source/package.nix { };
}
