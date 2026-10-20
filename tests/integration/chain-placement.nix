/*
  The placement probe: nft loads a base chain at exactly the family ×
  chain type × hook placements `validChainPlacement` accepts, and rejects
  the rest. A disagreement means the compatibility tables (or the kernel)
  changed.
*/
{
  fixtures,
  helpers,
  lib,
  nftlib,
  observations,
  ...
}:
let
  inherit (fixtures.chainPlacement) placements;
  record = observations.chainPlacement;

  # A loaded placement lists as a base chain of its type at its hook.
  loadsAsBaseChain = placement: helpers.runOutputIs "${placement.type} ${placement.hook}";

  isRejected = run: {
    expr = {
      failed = run.status != 0;
    }
    // lib.optionalAttrs (run.status == 0) { inherit (run) output; };
    expected.failed = true;
  };

  placementTest =
    placement:
    let
      run = record.${placement.name};
    in
    if nftlib.compatibility.validChainPlacement placement.family placement.type placement.hook then
      lib.nameValuePair "testLoadsAsBaseChain_${placement.name}" (loadsAsBaseChain placement run)
    else
      lib.nameValuePair "testRejected_${placement.name}" (isRejected run);
in
lib.listToAttrs (map placementTest placements)
// {
  testCaseNames = {
    expr = {
      count = builtins.length placements;
      recorded = builtins.attrNames (helpers.caseRuns record);
    };
    expected = {
      count = 126;
      recorded = lib.sort lib.lessThan (map (placement: placement.name) placements);
    };
  };
}
