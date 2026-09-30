/*
  Counter statement in its three forms (parser_json.c:1914): an inline
  anonymous counter, a reference to a named counter, and the stateless null
  form (e.g. `nft -j list --stateless`).
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Count packets and bytes that reach this statement.

    `counter { packets?; bytes?; }` builds an inline anonymous counter; the
    optional arguments seed its values. `counter.ref name` references a named
    counter object. `counter.auto` is the stateless `{ counter = null; }`
    form. Each returns a counter statement.
  */
  counter =
    variant
      (
        {
          packets ? null,
          bytes ? null,
        }:
        {
          counter = compact { inherit packets bytes; };
        }
      )
      {
        auto = {
          counter = null;
        };
        ref = name: { counter = name; };
      };
}
