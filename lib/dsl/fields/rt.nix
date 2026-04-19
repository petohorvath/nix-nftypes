{ lib }:

# Routing-data leaves. For `family`, use the escape hatch
# `dsl.expr.rt { key = …; family = "ip6"; }`.
#
#   fields.rt.mtu == { rt = { key = "mtu"; }; }

let
  keys = [
    "classid"
    "nexthop"
    "mtu"
  ];
in
lib.genAttrs keys (key: { rt = { inherit key; }; })
