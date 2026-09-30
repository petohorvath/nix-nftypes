/*
  Assemble the project's checks: the full package-set check set against
  stable `nixpkgs` (plain names — the floor consumers deploy on) and the same
  set against `nixpkgs-unstable` (`-unstable` suffix — where a newer
  nftables/lib lands first). This includes both live binaries and patched
  source, taken from the exported `nftables-source` packages.
*/
{
  packages,
  pkgs,
  pkgsUnstable,
}:
let
  inherit (pkgs) lib;
  suffixed = suffix: lib.mapAttrs' (name: lib.nameValuePair "${name}${suffix}");
  sourcePolicy = import ./nixpkgs-source-policy.nix { inherit pkgs; };
in
import ./package-set.nix {
  inherit pkgs;
  nftablesSource = packages.nftables-source;
}
// suffixed "-unstable" (
  import ./package-set.nix {
    pkgs = pkgsUnstable;
    nftablesSource = packages.nftables-source-unstable;
  }
)
// {
  nixpkgs-source-policy-tests = sourcePolicy.runTests pkgs;
}
