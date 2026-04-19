{ lib }:

# Conntrack-key leaves — plain value for each common key. For optional
# refinements (`dir` / `family`) use the escape hatch `dsl.expr.ct {…}`.
#
#   fields.ct.state == { ct = { key = "state"; }; }

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
    "proto-src"
    "proto-dst"
    "bytes"
    "packets"
    "avgpkt"
    "zone"
    "id"
    "count"
    "l3proto"
    "secmark"
    "event"
  ];

  # camelCase aliases for hyphenated keys.
  aliases = {
    protoSrc = "proto-src";
    protoDst = "proto-dst";
  };
in
(lib.genAttrs keys mkLeaf) // (lib.mapAttrs (_: mkLeaf) aliases)
