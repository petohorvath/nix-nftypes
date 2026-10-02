/*
  Render equivalence: each selected case, loaded through JSON and through
  text in separate network namespaces, must produce the same
  `nft list ruleset`. The strongest equivalence evidence for these cases:
  the schema, both renderers, and both live parser paths must agree.
  Cases that need kernel state the sandbox can't materialise are excluded
  in the fixture.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  runs = observations.renderEquivalence;
in
lib.listToAttrs (
  lib.concatMap (
    case:
    let
      json = runs."${case.name}-json";
      text = runs."${case.name}-text";
    in
    [
      (lib.nameValuePair "testLoadsJson_${case.name}" (helpers.probeSucceeds json))
      (lib.nameValuePair "testLoadsText_${case.name}" (helpers.probeSucceeds text))
      (lib.nameValuePair "testListingsMatch_${case.name}" {
        expr = text.output;
        expected = json.output;
      })
    ]
  ) fixtures.integrationCases.equivalenceCases
)
