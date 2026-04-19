{ lib }:

# FIB-result leaves. For `flags`, use the escape hatch
# `dsl.expr.fib { result = "oif"; flags = [ "saddr" "mark" ]; }`.
#
#   fields.fib.oif == { fib = { result = "oif"; }; }

let
  results = [
    "oif"
    "oifname"
    "type"
  ];
in
lib.genAttrs results (result: { fib = { inherit result; }; })
