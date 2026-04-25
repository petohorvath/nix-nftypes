{ lib }:

# Routing-data leaves. For `family`, use the escape hatch
# `dsl.expr.rt { key = …; family = "ip6"; }`.
#
#   fields.rt.mtu   == { rt = { key = "mtu"; }; }
#   fields.rt.ipsec == { rt = { key = "ipsec"; }; }

let
  keys = [
    "classid"
    "nexthop"
    "mtu"
    "ipsec"
  ];
in
lib.genAttrs keys (key: { rt = { inherit key; }; })
