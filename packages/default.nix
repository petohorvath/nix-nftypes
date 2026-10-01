/*
  Patched source trees are exposed for the scheduled branch-tip comparison
  and for manual inspection. The matching binaries remain the ordinary
  `pkgs.nftables` packages from each flake input.
*/
{ pkgs, pkgsUnstable }:
{
  nftables-source = pkgs.callPackage ./nftables-source/package.nix { };
  nftables-source-unstable = pkgsUnstable.callPackage ./nftables-source/package.nix { };
}
