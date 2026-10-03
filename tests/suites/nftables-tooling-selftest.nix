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
  observations,
  ...
}:
let
  runs = observations.nftablesToolingSelftest;
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

  # An unbaselined corpus statement must be classified as new drift.
  testCorpusFlagsUnbaselinedStatement = {
    expr = (helpers.corpusDrift observations.nftablesToolingSelftestCorpus).newDrift != [ ];
    expected = true;
  };
}
