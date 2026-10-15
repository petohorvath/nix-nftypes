/*
  Conntrack-key leaves — plain value for each common key. For optional
  refinements (`dir` / `family`) use the escape hatch `dsl.expr.ct {…}`.

    fields.ct.state == { ct = { key = "state"; }; }
*/
{ lib }:

let
  mkLeaf = key: { ct = { inherit key; }; };

  # The schema declares `ct.key` as `types.str`, so this list is the commonly
  # useful subset. Unusual keys are reachable via `dsl.expr.ct { key = …; }`.
  keys = [
    "state"
    "direction"
    "status"
    "mark"
    "expiration"
    "helper"
    "label"
    "saddr"
    "daddr"
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

  # Hyphenated keys, under their camelCase leaf names (ADR 0009).
  renamedKeys = {
    protoSrc = "proto-src";
    protoDst = "proto-dst";
  };
in
(lib.genAttrs keys mkLeaf) // (lib.mapAttrs (_: mkLeaf) renamedKeys)
