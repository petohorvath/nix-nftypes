{ lib }:

# FIB-result leaves. For `flags`, use the escape hatch
# `dsl.expr.fib { result = "oif"; flags = [ "saddr" "mark" ]; }`.
# Note: parser_json.c:1213-1230 enforces saddr⊕daddr (exactly one) and
# iif⊕oif (mutually exclusive), so a bare `fields.fib.<result>` without
# the escape hatch's `flags` is rejected by `nft -c` for everything but
# explicit-flag callers.
#
#   fields.fib.oif   == { fib = { result = "oif"; }; }
#   fields.fib.check == { fib = { result = "check"; }; }   # NFT_FIB_F_PRESENT predicate

let
  results = [
    "oif"
    "oifname"
    "type"
    "check"
  ];
in
lib.genAttrs results (result: { fib = { inherit result; }; })
