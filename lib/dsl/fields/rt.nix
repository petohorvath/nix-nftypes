/*
  Routing-data leaves, one for each key. `dsl.expr.rt` builds a key with
  its `family`, as in `dsl.expr.rt { key = …; family = "ip6"; }`, and
  throws without one, pointing here.

    fields.rt.mtu   == { rt = { key = "mtu"; }; }
    fields.rt.ipsec == { rt = { key = "ipsec"; }; }
*/
{ lib }:

let
  keys = [
    "classid"
    "nexthop"
    "mtu"
    "ipsec"
  ];
in
lib.genAttrs keys (key: {
  rt = { inherit key; };
})
