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
lib.concatMapAttrs (
  name: _:
  lib.genAttrs' [ "compact" "pretty" ] (
    form:
    lib.nameValuePair "testAccepted_${name}_${form}" (
      helpers.probeSucceeds observations.textBlockIntegration."${name}-${form}"
    )
  )
) fixtures.blockTables.integrationTables
