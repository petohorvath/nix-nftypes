/*
  Source provenance: the tree the source suites analyse must carry the
  exact release source, patch set, and patch hooks of the package set's
  nftables package, not an independent upstream pin or the raw, unpatched
  archive.
  Other source results are not trustworthy if this fails.
*/
{
  helpers,
  lib,
  observations,
  ...
}:
let
  paths = [
    "corpus"
    "parser"
    "serializer"
  ];
in
helpers.sourceProvenanceTests observations.nftablesSourceProvenance
// lib.genAttrs' paths (
  path:
  lib.nameValuePair "testSourceTreeHas_${path}" (
    helpers.runSucceeds observations.nftablesSourceTree.${path}
  )
)
// {
  testSourceTreeCaseNames = {
    expr = builtins.attrNames observations.nftablesSourceTree;
    expected = paths;
  };
}
