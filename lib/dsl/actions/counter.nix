/*
  Counter statement in its three forms (parser_json.c:1894-1920): an inline
  anonymous counter, a reference to a named counter, and the null form
  (e.g. `nft -j list --stateless`).
*/
{ lib }:

let
  variant = import ../internal/variant.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
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
    statement.
  */
  counter =
    variant
      (
        {
          packets ? null,
          bytes ? null,
        }:
        if packets == null || bytes == null then
          throw "nix-nftypes: dsl.counter: an inline counter needs both packets and bytes; use counter.auto for an unseeded counter"
        else
          {
            counter = { inherit packets bytes; };
          }
      )
      {
        auto = {
          counter = null;
        };
        ref = ref: { counter = reference.objectReference "counter.ref" ref; };
      };
}
