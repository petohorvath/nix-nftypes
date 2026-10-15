/*
  Conntrack statements. `ctHelper`, `ctTimeout`, and `ctExpectation` assign
  a named object to the flow through `.ref`; `ctCount` is a
  connection-count threshold check.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
in
{
  /*
    Assign a conntrack helper to the flow. `ctHelper.ref ref` names the
    ct helper object: `ref` is its name, with or without a leading `@`, or
    a map expression that selects one by key. Returns a `ct helper`
    statement.
  */
  ctHelper = reference.referenceOnly "ctHelper" "ct helper";

  /*
    Assign a conntrack timeout policy to the flow. `ctTimeout.ref ref`
    names the ct timeout object, as `ctHelper.ref` does. Returns a
    `ct timeout` statement.
  */
  ctTimeout = reference.referenceOnly "ctTimeout" "ct timeout";

  /*
    Assign a conntrack expectation to the flow. `ctExpectation.ref ref`
    names the ct expectation object, as `ctHelper.ref` does. Returns a
    `ct expectation` statement.
  */
  ctExpectation = reference.referenceOnly "ctExpectation" "ct expectation";

  /*
    Match on the number of tracked connections.

    `ctCount { val; inv?; }` checks the count against the threshold `val`,
    with `inv` optionally inverting the check. `ctCount.ref ref`
    references a named `ct count` object (nftables 1.1.7+), as
    `ctHelper.ref` does. Each returns a `ct count` statement.
  */
  ctCount =
    variant
      (
        {
          val,
          inv ? null,
        }:
        {
          "ct count" = compact { inherit val inv; };
        }
      )
      {
        ref = ref: { "ct count" = reference.objectReference "ctCount.ref" ref; };
      };
}
