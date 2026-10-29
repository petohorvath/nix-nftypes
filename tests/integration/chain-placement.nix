/*
  The placement probe: nft loads a base chain at exactly the family ×
  chain type × hook placements `validChainPlacement` accepts, and rejects
  the rest. A disagreement means the compatibility tables (or the kernel)
  changed.

  The priority probe: nft loads a filter chain at exactly the priority
  symbols `prioritiesByFamily` lists for its family and hook, at the
  listed value, and rejects the rest.
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
  inherit (fixtures.chainPlacement) placements prioritySymbols;
  placementRecord = observations.chainPlacement;
  symbolRecord = observations.prioritySymbols;

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
      run = placementRecord.${placement.name};
    in
    if nftlib.compatibility.validChainPlacement placement.family placement.type placement.hook then
      lib.nameValuePair "testLoadsAsBaseChain_${placement.name}" (loadsAsBaseChain placement run)
    else
      lib.nameValuePair "testRejected_${placement.name}" (isRejected run);

  # A loaded symbol lists as its value in the table.
  prioritySymbolTest =
    case:
    let
      run = symbolRecord.${case.name};
      priorities = nftlib.compatibility.prioritiesByFamily.${case.family}.${case.hook};
    in
    if priorities ? ${case.symbol} then
      lib.nameValuePair "testLoadsAtPriority_${case.name}" (
        helpers.runOutputIs (toString priorities.${case.symbol}) run
      )
    else
      lib.nameValuePair "testPriorityRejected_${case.name}" (isRejected run);

  caseNames = cases: lib.sort lib.lessThan (map (case: case.name) cases);
in
lib.listToAttrs (map placementTest placements)
// lib.listToAttrs (map prioritySymbolTest prioritySymbols)
// {
  testCaseNames = {
    expr = {
      count = builtins.length placements;
      recorded = builtins.attrNames (helpers.caseRuns placementRecord);
    };
    expected = {
      count = 126;
      recorded = caseNames placements;
    };
  };

  testPrioritySymbolCaseNames = {
    expr = {
      count = builtins.length prioritySymbols;
      recorded = builtins.attrNames (helpers.caseRuns symbolRecord);
    };
    expected = {
      count = 175;
      recorded = caseNames prioritySymbols;
    };
  };
}
