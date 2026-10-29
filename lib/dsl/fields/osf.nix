/*
  OS-fingerprint key leaves (parser_json.c:486-489), one for each key.
  `dsl.expr.osf` builds a key with its `ttl` ("loose"/"skip"), as in
  `dsl.expr.osf { key = …; ttl = "loose"; }`, and throws without one,
  pointing here.

    fields.osf.name    == { osf = { key = "name"; }; }
    fields.osf.version == { osf = { key = "version"; }; }
*/
{ lib }:

let
  keys = [
    "name"
    "version"
  ];
in
lib.genAttrs keys (key: {
  osf = { inherit key; };
})
