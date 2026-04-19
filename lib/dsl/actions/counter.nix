{ lib }:

# Counter statement. Three forms (parser_json.c:1914):
#   counter { packets?; bytes?; }    — inline anonymous counter
#   counter.ref "name"               — reference to a named counter
#   counter.auto                     — stateless null form (e.g. `nft -j list --stateless`)

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  counter = variant
    (
      { packets ? null, bytes ? null }:
      { counter = compact { inherit packets bytes; }; }
    )
    {
      auto = { counter = null; };
      ref = name: { counter = name; };
    };
}
