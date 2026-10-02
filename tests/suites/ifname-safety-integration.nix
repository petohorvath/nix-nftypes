/*
  Live round trip for interface-name sets: safe sets loaded through the
  JSON and text paths must keep exactly the declared element count.
  Pre-fix, a `[ "eth0,eth1" ]` element widened to two; this pins that the
  safe path preserves the count, so a return to bare-comma rendering would
  be noticed.
*/
{ observations, ... }:
let
  runs = observations.ifnameSafetyIntegration;
  elementCount = count: run: {
    expr = {
      inherit (run) output status;
    };
    expected = {
      output = toString count;
      status = 0;
    };
  };
in
{
  testJsonKeepsSingleElement = elementCount 1 runs.one-json;
  testTextKeepsSingleElement = elementCount 1 runs.one-text;
  testJsonKeepsTwoElements = elementCount 2 runs.two-json;
  testTextKeepsTwoElements = elementCount 2 runs.two-text;
}
