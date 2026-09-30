/*
  Materialize the exact source tree a package set provides, including every
  downstream patch from its nftables derivation. Source-inspection checks
  consume this tree while live-parser checks consume `pkgs.nftables`, so both
  directions share one nixpkgs-controlled authority.
*/
{
  applyPatches,
  lib,
  nftables,
}:
let
  prePatch = if nftables ? prePatch && nftables.prePatch != null then nftables.prePatch else "";
  postPatch = if nftables ? postPatch && nftables.postPatch != null then nftables.postPatch else "";
in
applyPatches (
  {
    name = "nftables-${nftables.version}-nixpkgs-source";
    inherit (nftables) src version;
    inherit postPatch prePatch;
    patches = nftables.patches or [ ];
  }
  // lib.optionalAttrs (nftables ? patchFlags && nftables.patchFlags != null) {
    inherit (nftables) patchFlags;
  }
  // lib.optionalAttrs (prePatch != "" || postPatch != "") {
    nativeBuildInputs = nftables.nativeBuildInputs or [ ];
  }
)
