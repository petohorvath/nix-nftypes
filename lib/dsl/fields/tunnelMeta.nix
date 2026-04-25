{ lib }:

# Tunnel-metadata leaves. Distinct from the `tunnel` named-object type and
# from the tunnel-inner-header payload form.
#   fields.tunnelMeta.id   == { tunnel = { key = "id"; }; }

let
  keys = [
    "path"
    "id"
  ];
in
lib.genAttrs keys (key: {
  tunnel = { inherit key; };
})
