/*
  Last statement in its two forms: seeded with the time the rule last
  matched, and the null form that nft lists for one never seeded.
*/
{ lib }:

let
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Record when the rule last matched.

    `last { used; }` seeds it with a previous last-used time; nft rejects
    an empty body, so a missing `used` throws. `last.auto` is
    the null form `{ last = null; }`, an unseeded record. Each returns a
    last statement.
  */
  last =
    variant
      (
        {
          used ? null,
        }:
        if used == null then
          throw "nix-nftypes: dsl.last: a seeded last needs used; use last.auto for an unseeded one"
        else
          {
            last = { inherit used; };
          }
      )
      {
        auto = {
          last = null;
        };
      };
}
