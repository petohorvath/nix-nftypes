/*
  Counter statement in its three forms (parser_json.c:1894-1920): an inline
  anonymous counter, a reference to a named counter, and the null form
  (e.g. `nft -j list --stateless`).
*/
{ lib, statement }:

let
  inherit (import ../internal/location.nix { inherit lib; }) fail;
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Count packets and bytes that reach this statement.

    `counter { packets; bytes; }` builds an inline anonymous counter seeded
    with both values; nft parses an inline counter only with both, so a
    missing one throws. `counter.ref ref` references a named counter
    object: `ref` is its name, with or without a leading `@`, or a map
    expression that selects one by key. `counter.auto` is the null form
    `{ counter = null; }`, an unseeded counter. Each returns a counter
    statement, and throws when its body doesn't validate.
  */
  counter =
    variant
      (statement.fromFields {
        name = "counter";
        prepare =
          location: body:
          if body ? packets && body ? bytes then
            body
          else
            fail location "an inline counter needs both packets and bytes; use counter.auto for an unseeded counter";
      })
      {
        auto = {
          counter = null;
        };
        ref = statement.ref { name = "counter"; };
      };
}
