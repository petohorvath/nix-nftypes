/*
  Tunnel-metadata leaves. Distinct from the `tunnel` Named object and
  from the tunnel-inner-header payload form.
    fields.tunnel.id == { tunnel = { key = "id"; }; }
*/
{ lib }:

let
  keys = [
    "path"
    "id"
  ];
in
lib.genAttrs keys (key: {
  tunnel = { inherit key; };
})
