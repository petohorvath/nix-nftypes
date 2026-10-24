/*
  Last statement in its two forms (parser_json.c:1923-1942): seeded with
  the time the rule last matched, and the null form that nft lists for one
  never seeded.
*/
{ lib, statement }:

let
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Record when the rule last matched.

    `last { used; }` seeds it with a previous last-used time; nft rejects
    an empty body, so a missing `used` throws. `last.auto` is
    the null form `{ last = null; }`, an unseeded record. Each returns a
    last statement; `last { … }` throws when its body doesn't validate.
  */
  last =
    variant
      (statement.fromFields {
        name = "last";
        prepare =
          body:
          if body ? used then
            body
          else
            throw "nix-nftypes: dsl.last: a seeded last needs used; use last.auto for an unseeded one";
      })
      {
        auto = {
          last = null;
        };
      };
}
