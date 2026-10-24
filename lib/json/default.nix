/*
  JSON renderer: produces the libnftables-json form consumed by
  `nft -j -f`. `clean` is injected from lib/clean.nix so the text renderer
  can share it without depending on this module.
*/
{ lib, clean }:

let
  requireRuleset = import ../require-ruleset.nix { inherit lib; };
in
{
  /*
    Serialize a ruleset to compact libnftables JSON.

    `ruleset` is `{ nftables = [ … ]; }`, as `dsl.ruleset` builds it. It is
    cleaned first, which drops unset nullable fields and module markers; it
    is not type-checked. Anything else throws, a lone command or a table
    tree included: wrap it in `dsl.ruleset [ … ]`.

    Returns the JSON string.
  */
  toJson = ruleset: builtins.toJSON (clean (requireRuleset "toJson" ruleset));
}
