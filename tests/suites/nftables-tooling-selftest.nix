/*
  Red-path self-tests for the source tooling (docs/upstream-sync.md). The
  drift suites exist to turn silent schema rot into red CI, so the worst
  failure mode is the tooling itself rotting silently GREEN: an
  extraction regex that stops matching, a baseline that swallows
  everything. Each probe run injects a defect and these tests assert the
  machinery reports it. The read-back validator's red paths are in the
  schema suite.
*/
{
  helpers,
  lib,
  observations,
  ...
}:
let
  runs = observations.nftablesToolingSelftest;

  # The source-provenance tests that fail on a doctored record, with what
  # each reported.
  provenanceFailures =
    record:
    lib.pipe (helpers.sourceProvenanceTests record) [
      (lib.filterAttrs (_: test: test.expr != test.expected))
      (lib.mapAttrs (_: test: test.expr))
    ];
in
{
  # Schema without rtKey "ipsec": the checker must name the token.
  testEnumDriftDetected = helpers.runFailsWith [
    "DRIFT DETECTED"
    "ipsec"
  ] runs.enumDrift;

  # Schema without the `tproxy` statement tag.
  testTagDriftDetected = helpers.runFailsWith [
    "DRIFT DETECTED"
    "tproxy"
  ] runs.tagDrift;

  # A renamed C table must fail loudly, not pass vacuously.
  testRenamedTableFailsExtraction = helpers.runFailsWith [
    "EXTRACTION FAILURE"
  ] runs.renamedTable;

  # A table body the regex can no longer read trips the floor.
  testUnreadableTableTripsFloor = helpers.runFailsWith [
    "plausibility floor"
  ] runs.unreadableTable;

  testUndoctoredInputsPass = helpers.runSucceeds runs.control;

  # A package `postPatch` that the source tree drops.
  testProvenanceFlagsDroppedPostPatch = {
    expr = builtins.attrNames (
      provenanceFailures observations.nftablesToolingSelftestProvenance.droppedPostPatch
    );
    expected = [ "testInheritsPackagePostPatch" ];
  };

  # A package `postUnpack` that the source package does not pass.
  testProvenanceNamesUnpassedAttribute = {
    expr = provenanceFailures observations.nftablesToolingSelftestProvenance.unpassedPostUnpack;
    expected.testPackageSetsNoUnpassedAttributes = [ "postUnpack" ];
  };

  # An unbaselined corpus statement must be classified as new drift.
  testCorpusFlagsUnbaselinedStatement = {
    expr = (helpers.corpusDrift observations.nftablesToolingSelftestCorpus).newDrift != [ ];
    expected = true;
  };
}
