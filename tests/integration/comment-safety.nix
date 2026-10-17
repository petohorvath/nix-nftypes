/*
  Live round trip for comments: a safe table comment loaded through the
  JSON and text paths must read back from `nft -j list ruleset`
  byte-for-byte, byte 0xA0 included.
*/
{
  fixtures,
  helpers,
  observations,
  ...
}:
let
  runs = observations.commentSafetyIntegration;
  readsBackComment = helpers.runOutputIs fixtures.roundTripComment;
in
{
  testJsonRoundTripsComment = readsBackComment runs.comment-json;
  testTextRoundTripsComment = readsBackComment runs.comment-text;
  testJsonRoundTripsByteA0 = helpers.runOutputIs fixtures.byteA0Comment runs.byte-a0-json;
  testTextRoundTripsByteA0 = helpers.runOutputIs fixtures.byteA0Comment runs.byte-a0-text;

  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns runs);
    expected = [
      "byte-a0-json"
      "byte-a0-text"
      "comment-json"
      "comment-text"
    ];
  };
}
