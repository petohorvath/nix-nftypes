/*
  Conntrack-key leaves — plain value for each common key. For optional
  refinements (`dir` / `family`) use the escape hatch `dsl.expr.ct {…}`.

    fields.ct.state == { ct = { key = "state"; }; }
*/
{ lib }:

let
  # The schema declares `ct.key` as `types.str`, so this list is the commonly
  # useful subset. Unusual keys are reachable via `dsl.expr.ct { key = …; }`.
  # `saddr`, `daddr`, `proto-src`, and `proto-dst` have no leaf: nft loads
  # them only with a `dir`, so they are built with `dsl.expr.ct`.
  keys = [
    "state"
    "direction"
    "status"
    "mark"
    "expiration"
    "helper"
    "label"
    "protocol"
    "bytes"
    "packets"
    "avgpkt"
    "zone"
    "id"
    "l3proto"
    "secmark"
    "event"
  ];
in
lib.genAttrs keys (key: {
  ct = { inherit key; };
})
