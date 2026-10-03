/*
  Source provenance: the tree the source suites analyse must carry the
  exact release source and patch set of the package set's nftables
  package, not an independent upstream pin or the raw, unpatched archive.
  Other source results are not trustworthy if this fails.
*/
{
  helpers,
  lib,
  observations,
  ...
}:
let
  inherit (observations.nftablesSourceProvenance) package source;
in
{
  testInheritsPackageSource = {
    expr = source.src;
    expected = package.src;
  };

  testInheritsPackagePatches = {
    expr = source.patches;
    expected = package.patches;
  };
}
// lib.genAttrs' [ "parser" "serializer" "corpus" ] (
  path:
  lib.nameValuePair "testSourceTreeHas_${path}" (
    helpers.runSucceeds observations.nftablesSourceTree.${path}
  )
)
