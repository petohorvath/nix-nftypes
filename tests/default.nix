/*
  Assemble the project's checks: the full package-set check set against
  stable `nixpkgs` (plain names — the floor consumers deploy on) and the same
  set against `nixpkgs-unstable` (`-unstable` suffix — where a newer
  nftables/lib lands first). This includes both live binaries and patched
  source, taken from the exported `nftables-source` packages.

  A divergence between the two package sets' `nft` (or `lib` module system)
  turns a check red instead of surfacing in a consumer's deployment.

  nftables has no independent flake input. Each compatibility surface uses
  the exact binary, release source, and downstream patches carried by its
  nixpkgs package set. This keeps the test oracle identical to what
  consumers install and avoids a second, fragile upstream-Git authority.
*/
{
  packages,
  pkgs,
  pkgsUnstable,
}:
let
  inherit (pkgs) lib;
  addNameSuffix = suffix: lib.mapAttrs' (name: lib.nameValuePair "${name}${suffix}");
  sourcePolicy = import ./nixpkgs-source-policy.nix { inherit pkgs; };
in
import ./package-set.nix {
  inherit pkgs;
  nftablesSource = packages.nftables-source;
}
// addNameSuffix "-unstable" (
  import ./package-set.nix {
    pkgs = pkgsUnstable;
    nftablesSource = packages.nftables-source-unstable;
  }
)
// {
  nixpkgs-source-policy-tests = sourcePolicy.runTests pkgs;
}
