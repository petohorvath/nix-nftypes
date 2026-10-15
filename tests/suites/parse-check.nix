/*
  Parse check: every pinned text string, every Field leaf and every
  expected DSL parity JSON value (fixtures/parse-check.nix) must pass the
  package set's `nft -c`. An expected rejection that applies to the
  recorded nft and kernel versions must still fail with its error
  instead, so a fixed pending entry fails until its fix removes it.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  inherit (fixtures.parseCheck) checks expectedRejections;
  runs = observations.parseCheck;

  checkRuns = removeAttrs (helpers.caseRuns runs) [ "kernelVersion" ];

  nftVersion = helpers.nftVersion runs;
  kernelVersion = lib.head (builtins.match "([0-9]+\\.[0-9]+).*" runs.kernelVersion.output);

  applies =
    entry:
    (entry ? rejectedBefore -> helpers.rejectedOn nftVersion entry)
    && (entry ? kernelFrom -> !(lib.versionOlder kernelVersion entry.kernelFrom));

  rejected = lib.filterAttrs (_: applies) expectedRejections;

  # The source a check name comes from: a parity suite, or `leaf.json` or
  # `leaf.text`.
  sourceOf =
    name:
    let
      parts = lib.splitString "." name;
    in
    if builtins.head parts == "leaf" then
      lib.concatStringsSep "." (lib.take 2 parts)
    else
      builtins.head parts;

  # The run failed in nft, with one of `entry.error` in its output.
  stillRejected =
    entry: run:
    let
      failed = run.status != 0;
      reported = lib.any (error: lib.hasInfix error run.output) (lib.toList entry.error);
    in
    {
      expr = {
        inherit failed reported;
      }
      // lib.optionalAttrs (!(failed && reported)) { inherit (run) output; };
      expected = {
        failed = true;
        reported = true;
      };
    };
in
{
  testRunsAreTheChecks = {
    expr = builtins.attrNames checkRuns;
    expected = builtins.attrNames checks;
  };

  # The checks are enumerated, so each source must still yield some.
  testEverySourceHasChecks = {
    expr = builtins.attrNames (lib.groupBy sourceOf (builtins.attrNames checkRuns));
    expected = [
      "dslParity"
      "leaf.json"
      "leaf.text"
      "textBlockParity"
      "textParity"
    ];
  };
}
// lib.mapAttrs' (
  name: _: lib.nameValuePair "testParses_${name}" (helpers.runSucceeds runs.${name})
) (removeAttrs checks (builtins.attrNames rejected))
// lib.mapAttrs' (
  name: entry: lib.nameValuePair "testStillRejected_${name}" (stillRejected entry runs.${name})
) rejected
