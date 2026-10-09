/*
  Assemble the project's checks and VM tests: the package-set test set
  against `nixpkgs`, including both the live binary and the patched source
  taken from the exported `nftables-source` package.

  The tests cover one package set per evaluation. The project policy reruns
  `nix flake check` with its stable and unstable pins overriding `nixpkgs`,
  so a newer nftables (or `lib` module system) turns a test red instead of
  surfacing in a consumer's deployment.

  nftables has no independent flake input. Each compatibility surface uses
  the exact binary, release source, and downstream patches carried by the
  nixpkgs package set. This keeps the test oracle identical to what
  consumers install and avoids a second, fragile upstream-Git authority.
*/
{ packages, pkgs }:
import ./package-set.nix {
  inherit pkgs;
  nftablesSource = packages.nftables-source;
}
