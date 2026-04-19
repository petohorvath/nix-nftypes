{ lib }:

# IPsec (xfrm) leaves. For `family` / `dir` / `spnum`, use the escape hatch
# `dsl.expr.ipsec { key = …; family = "ip"; dir = "in"; }`.
#
#   fields.ipsec.reqid == { ipsec = { key = "reqid"; }; }

let
  keys = [
    "saddr"
    "daddr"
    "reqid"
    "spi"
  ];
in
lib.genAttrs keys (key: { ipsec = { inherit key; }; })
