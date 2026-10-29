/*
  "Still misbehaves": each case in ../fixtures/nft-misbehaviour.nix must
  still produce its recorded misbehaviour. A failure means nft no longer
  misbehaves: revisit the Known difference, and let the form return to the
  schema (ADR 0010).
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  inherit (fixtures.nftMisbehaviour) cases;
  record = observations.nftMisbehaviour;
  version = helpers.nftVersion record;

  # An nft older than the case's `rejectedBefore` rejects the form instead,
  # and one from the case's `fixedFrom` on loads it as written.
  expectedOutput =
    case:
    if helpers.rejectedOn version case then
      case.rejection
    else if case ? fixedFrom && !(lib.versionOlder version case.fixedFrom) then
      case.fixed
    else
      case.misbehaviour;
in
lib.listToAttrs (
  map (
    case:
    lib.nameValuePair "testStillMisbehaves_${case.name}" (
      helpers.runStillMisbehaves (expectedOutput case) record.${case.name}
    )
  ) cases
)
// {
  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns record);
    expected = [
      "add-handle-ignored"
      "add-rule-handle-ignored-on-json"
      "chain-hook-without-type"
      "chain-prio-without-hook"
      "chain-type-without-hook"
      "chain-without-hook"
      "chain-without-prio"
      "chain-without-type"
      "delete-ct-count-aborts"
      "delete-ct-expectation-deletes-table"
      "delete-ct-timeout-fails"
      "delete-rule-handle-zero-deletes-every-rule"
      "delete-tunnel-aborts"
      "destroy-ct-count-aborts"
      "destroy-ct-expectation-deletes-table"
      "destroy-ct-timeout-unsupported"
      "destroy-rule-handle-zero-deletes-every-rule"
      "destroy-tunnel-aborts"
      "element-statements-ignored-on-json"
      "list-ct-expectation-lists-table"
      "list-ct-timeout-aborts"
      "list-tunnel-aborts"
      "listed-meter-rejected-on-json"
      "payload-l4proto-loads-header-field"
      "reset-before-another-command-resets-nothing"
      "reset-runs-only-the-last"
      "set-comment-ignored-on-json"
      "tunnel-dport-loads-as-sport"
    ];
  };
}
