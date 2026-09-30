/*
  Conntrack statements. `ctHelper`, `ctTimeout`, and `ctExpectation` assign
  a named object to the flow; `ctCount` is a connection-count threshold
  check.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  /*
    Assign a conntrack helper to the flow. `e` is the helper expression,
    typically a named object reference. Returns a `ct helper` statement.
  */
  ctHelper = e: { "ct helper" = e; };

  /*
    Assign a conntrack timeout policy to the flow. `e` is the timeout
    expression, typically a named object reference. Returns a `ct timeout`
    statement.
  */
  ctTimeout = e: { "ct timeout" = e; };

  /*
    Assign a conntrack expectation to the flow. `e` is the expectation
    expression, typically a named object reference. Returns a
    `ct expectation` statement.
  */
  ctExpectation = e: { "ct expectation" = e; };

  /*
    Match on the number of tracked connections. `val` is the threshold and
    `inv` optionally inverts the check. Returns a `ct count` statement.
  */
  ctCount =
    {
      val,
      inv ? null,
    }:
    {
      "ct count" = compact { inherit val inv; };
    };
}
