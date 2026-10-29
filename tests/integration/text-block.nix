/*
  Live block parser: each integration table, rendered in compact and
  pretty block form and wrapped in `table <family> <name> { … }`, must
  pass the package set's `nft -c -f`.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  record = observations.textBlockIntegration;
in
lib.concatMapAttrs (
  name: _:
  lib.genAttrs' [ "compact" "pretty" ] (
    form:
    lib.nameValuePair "testAccepted_${name}_${form}" (helpers.runSucceeds record."${name}-${form}")
  )
) fixtures.blockTables.integrationTables
// {
  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns record);
    expected =
      lib.concatMap
        (name: [
          "${name}-compact"
          "${name}-pretty"
        ])
        [
          "chain-object-references"
          "chain-with-rules"
          "inline-and-named-limits"
          "minimal-base-chain"
          "mixed-chain-set-counter"
          "set-with-inline-elements"
          "symbolic-priority-chains"
        ];
  };
}
