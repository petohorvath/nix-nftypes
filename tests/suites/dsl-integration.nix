/*
  Live JSON parser: each integration case's JSON must pass the package
  set's `nft -c -j -f`, and each parser-negative case must be rejected for
  its stated reason. Stricter than schema validation: the parser resolves
  cross-references, rejects divergences from its own expectations, and
  catches shape mismatches evalModules couldn't.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  inherit (fixtures) integrationCases;
  runs = observations.dslIntegration;
in
lib.listToAttrs (
  map (
    case: lib.nameValuePair "testAccepted_${case.name}" (helpers.probeSucceeds runs.${case.name})
  ) integrationCases.cases
  # The raw rejection cases bypass the schema so the live parser stays the
  # oracle; the diagnostic pins rejection to the unsupported command rather
  # than an unrelated missing-state error.
  ++ map (
    case:
    lib.nameValuePair "testRejected_${case.name}" (
      helpers.probeFailsWith [ case.expectedError ] runs.${case.name}
    )
  ) integrationCases.rejectionCases
)
