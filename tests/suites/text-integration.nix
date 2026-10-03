/*
  Live text parser: each integration case that render equivalence cannot
  load, rendered with toTextPretty, must pass the package set's
  `nft -c -f`. Render equivalence real-loads the other text cases, which
  covers everything check mode would.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
lib.listToAttrs (
  map (
    case:
    lib.nameValuePair "testAccepted_${case.name}" (
      helpers.runSucceeds observations.textIntegration.${case.name}
    )
  ) fixtures.integrationCases.textCheckOnlyCases
)
