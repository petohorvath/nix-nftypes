{ lib }:

# Socket-key leaves.
#   fields.socket.transparent == { socket = { key = "transparent"; }; }

let
  keys = [
    "transparent"
    "mark"
    "wildcard"
  ];
in
lib.genAttrs keys (key: {
  socket = { inherit key; };
})
