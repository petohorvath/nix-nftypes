/*
  Live round trip for interface-name sets: safe sets loaded through the
  JSON and text paths must keep exactly the declared element count.
  Pre-fix, a `[ "eth0,eth1" ]` element widened to two; this pins that the
  safe path preserves the count, so a return to bare-comma rendering would
  be noticed.
*/
{
  helpers,
  observations,
  ...
}:
let
  runs = observations.ifnameSafetyIntegration;
  hasElements = count: helpers.runOutputIs (toString count);
in
{
  testJsonKeepsSingleElement = hasElements 1 runs.one-json;
  testTextKeepsSingleElement = hasElements 1 runs.one-text;
  testJsonKeepsTwoElements = hasElements 2 runs.two-json;
  testTextKeepsTwoElements = hasElements 2 runs.two-text;
}
