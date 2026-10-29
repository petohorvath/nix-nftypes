/*
  Live JSON parser: each integration case's JSON must pass the package
  set's `nft -c -j -f`. Stricter than schema validation: the parser
  resolves cross-references, rejects divergences from its own
  expectations, and catches shape mismatches evalModules couldn't.

  Each negative case is one wrong value that the schema and nft must both
  reject: nft with the case's diagnostic, and the schema while it accepts
  the same ruleset with the value corrected, so a test fails when either
  side's strictness drifts. The placement probe (chain-placement.nix)
  does the same for every chain placement `validChainPlacement` forbids.
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
  inherit (fixtures) integrationCases;
  runs = observations.dslIntegration;
  version = helpers.nftVersion runs;

  validates = helpers.validates nftlib.types.ruleset;
in
lib.listToAttrs (
  map (
    case:
    # A case that only a newer nft accepts must be rejected by an older one.
    if helpers.rejectedOn version case then
      lib.nameValuePair "testRejected_${case.name}" (helpers.runFailsWith [ ] runs.${case.name})
    else
      lib.nameValuePair "testAccepted_${case.name}" (helpers.runSucceeds runs.${case.name})
  ) integrationCases.cases
  # The diagnostic pins nft's rejection to the wrong value rather than an
  # unrelated missing-state error.
  ++ lib.concatMap (case: [
    (lib.nameValuePair "testRejected_${case.name}" (
      helpers.runFailsWith [ case.expectedError ] runs.${case.name}
    ))
    (lib.nameValuePair "testSchemaRejects_${case.name}" {
      expr = {
        accepted = validates (case.withValue case.accepted);
        rejected = validates case.ruleset;
      };
      expected = {
        accepted = true;
        rejected = false;
      };
    })
  ]) integrationCases.rejectionCases
)
// {
  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns runs);
    expected = lib.sort lib.lessThan (
      fixtures.integrationCaseNames
      ++ [
        "boolean-object-reference"
        "create-rule"
        "flowtable-hook-other-than-ingress"
        "port-out-of-range"
        "reset-other-than-tcp-option"
        "unknown-chain-policy"
        "unknown-family"
        "unknown-hook"
        "unknown-log-level"
        "unknown-relational-op"
      ]
    );
  };
}
