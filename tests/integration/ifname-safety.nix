/*
  Live round trip for interface-name sets: sets loaded through the JSON
  and text paths must keep exactly the declared element count. Text
  quotes each element, so `eth0,eth1` stays one element; bare, it
  widened the set to two.
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
  testJsonKeepsCommaInOneElement = hasElements 1 runs.comma-json;
  testTextKeepsCommaInOneElement = hasElements 1 runs.comma-text;

  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns runs);
    expected = [
      "comma-json"
      "comma-text"
      "one-json"
      "one-text"
      "two-json"
      "two-text"
    ];
  };
}
