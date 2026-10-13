/*
  The source-provenance assertions over one provenance record
  (`nftablesSourceProvenance` in ../probes/source.nix). The provenance
  suite runs them on the package set's record; the tooling self-test runs
  them on doctored records to prove that they turn red.
*/
{ lib }:
record:
let
  inherit (record) package source;
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

  testInheritsPackagePatchFlags = {
    expr = source.patchFlags;
    expected = package.patchFlags;
  };

  testInheritsPackagePrePatch = {
    expr = source.prePatch;
    expected = package.prePatch;
  };

  testInheritsPackagePostPatch = {
    expr = source.postPatch;
    expected = package.postPatch;
  };

  # The source package passes none of these, so a package that sets one
  # builds from a different tree; the failure names the attribute.
  testPackageSetsNoUnpassedAttributes = {
    expr = builtins.attrNames (lib.filterAttrs (_: value: value != null) package.unpassed);
    expected = [ ];
  };
}
