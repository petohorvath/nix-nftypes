/*
  Live text parser: each integration case outside the known text-grammar
  limitations, rendered with toTextPretty, must pass the package set's
  `nft -c -f`.
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
      helpers.probeSucceeds observations.textIntegration.${case.name}
    )
  ) fixtures.integrationCases.textCases
)
