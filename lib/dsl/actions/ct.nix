{ lib }:

# Conntrack statements: ctHelper / ctTimeout / ctExpectation set a reference
# on the flow (body is an expression — typically a string ref). ctCount is a
# threshold check with optional invert.

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  ctHelper = e: { "ct helper" = e; };
  ctTimeout = e: { "ct timeout" = e; };
  ctExpectation = e: { "ct expectation" = e; };

  ctCount =
    {
      val,
      inv ? null,
    }:
    {
      "ct count" = compact { inherit val inv; };
    };
}
