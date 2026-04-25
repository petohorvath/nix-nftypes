{ lib }:

# OS-fingerprint key leaves. For `ttl` ("loose"/"skip"), use the escape
# hatch `dsl.expr.osf { key = …; ttl = "loose"; }`.
#
#   fields.osf.name    == { osf = { key = "name"; }; }
#   fields.osf.version == { osf = { key = "version"; }; }   # parser_json.c:486-489

let
  keys = [
    "name"
    "version"
  ];
in
lib.genAttrs keys (key: { osf = { inherit key; }; })
