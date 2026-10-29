/*
  Conntrack-key leaves, one for each key nft loads without a direction.
  `dsl.expr.ct` builds a key with its direction (`dir`), and throws
  without one, pointing here.

    fields.ct.state == { ct = { key = "state"; }; }
*/
{ lib }:

let
  # Every ct key nft loads without a direction. `saddr`, `daddr`,
  # `proto-src`, `proto-dst`, and the `ip` and `ip6` addresses have no leaf:
  # nft loads them only with a direction, so `dsl.expr.ct` builds them.
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
