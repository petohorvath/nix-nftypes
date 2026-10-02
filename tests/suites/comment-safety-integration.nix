/*
  Live round trip for comments: a safe table comment loaded through the
  JSON and text paths must read back from `nft -j list ruleset`
  byte-for-byte.
*/
{
  fixtures,
  observations,
  ...
}:
let
  readBack = run: {
    expr = {
      inherit (run) output status;
    };
    expected = {
      output = fixtures.roundTripComment;
      status = 0;
    };
  };
in
{
  testJsonRoundTripsComment = readBack observations.commentSafetyIntegration.json;
  testTextRoundTripsComment = readBack observations.commentSafetyIntegration.text;
}
