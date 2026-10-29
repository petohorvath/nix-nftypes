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

  inherit (helpers.tokenDrift) models tables;
  extracted = builtins.fromJSON runs.control.output;

  # The Drift of one table whose model list `edit` changes.
  editedModelDrift =
    name: edit:
    (helpers.tokenDrift.drift (models // { ${name} = edit models.${name}; }) extracted).${name};

  # One token per table, each in the source and the model; G1 and G3 of
  # docs/spec-coverage.md for rtKey and fibResult.
  modelTokens = {
    byteUnit = "kbytes";
    ctDirKey = "zone";
    ctKey = "secmark";
    expressionTag = "osf";
    family = "netdev";
    fibResult = "check";
    limitRateUnit = "kbytes";
    metaKey = "secmark";
    rtKey = "ipsec";
    statementTag = "tproxy";
  };

  # Runs whose source lacks one entry of a table, by table.
  missingEntryRuns = lib.pipe runs [
    (lib.filterAttrs (name: _: lib.hasPrefix "missingEntry_" name))
    (lib.mapAttrs' (name: run: lib.nameValuePair (lib.removePrefix "missingEntry_" name) run))
  ];
in
lib.mapAttrs' (
  name: run:
  lib.nameValuePair "testMissingSourceEntryFails_${name}" (
    helpers.runFailsWith [
      "EXTRACTION FAILURE"
      "below its floor"
    ] run
  )
) missingEntryRuns
// {
  # A model without one of a table's tokens is Drift.
  testEnumDriftFindsTokenMissingFromModel = {
    expr = lib.mapAttrs (
      name: token: (editedModelDrift name (lib.remove token)).missingFromModel
    ) modelTokens;
    expected = lib.mapAttrs (_: token: [ token ]) modelTokens;
  };

  # A model token that no table holds is Drift too.
  testEnumDriftFindsTokenMissingFromSource = {
    expr = lib.mapAttrs (
      name: _: (editedModelDrift name (tokens: tokens ++ [ "wug" ])).missingFromSource
    ) models;
    expected = lib.mapAttrs (_: _: [ "wug" ]) models;
  };

  # Every table has a run that drops one of its entries.
  testEveryTableLosesAnEntry = {
    expr = builtins.attrNames missingEntryRuns;
    expected = tables;
  };

  # A renamed C table must fail loudly, not pass vacuously.
  testRenamedTableFailsExtraction = helpers.runFailsWith [
    "EXTRACTION FAILURE"
  ] runs.renamedTable;

  # A table body the regex can no longer read trips the floor.
  testUnreadableTableTripsFloor = helpers.runFailsWith [
    "below its floor"
  ] runs.unreadableTable;

  # Entries written as designated initializers, `{ .name = "ip", … }`,
  # yield the same tokens as positional ones.
  testDesignatedEntriesExtracted = {
    expr = builtins.fromJSON runs.designatedEntries.output;
    expected = extracted;
  };

  testUndoctoredInputsPass = helpers.runSucceeds runs.control;

  testCaseNames = {
    expr = builtins.attrNames runs;
    expected = [
      "control"
      "designatedEntries"
      "missingEntry_byteUnit"
      "missingEntry_ctDirKey"
      "missingEntry_ctKey"
      "missingEntry_expressionTag"
      "missingEntry_family"
      "missingEntry_fibResult"
      "missingEntry_metaKey"
      "missingEntry_rtKey"
      "missingEntry_statementTag"
      "renamedTable"
      "unparsableCorpusRecord"
      "unreadableTable"
    ];
  };

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

  # A bracket in a title is not the record's array.
  testCorpusKeepsBracketedTitles = {
    expr = map (record: record.title) observations.nftablesToolingSelftestCorpus;
    expected = [
      "frobnicate the wug"
      "dnat to [2001:db8::1]:80"
      "srh sid[1] dead::beef"
    ];
  };

  # A record without a parsable array fails the normalizer, naming it.
  testCorpusRejectsUnparsableRecord = helpers.runFailsWith [
    "UNPARSABLE CORPUS RECORD"
    "half an array"
  ] runs.unparsableCorpusRecord;

  # An unbaselined corpus statement must be classified as new drift.
  testCorpusFlagsUnbaselinedStatement = {
    expr = (helpers.corpusDrift observations.nftablesToolingSelftestCorpus).newDrift != [ ];
    expected = true;
  };
}
