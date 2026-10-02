/*
  Live round trip for comments: a safe table comment loaded through the
  JSON and text paths must read back from `nft -j list ruleset`
  byte-for-byte.
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
}
