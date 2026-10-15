/*
  JSON renderer: produces the libnftables-json form consumed by
  `nft -j -f`. `clean` is injected from lib/clean.nix so the text renderer
  can share it without depending on this module.
*/
{ lib, clean }:

let
  inherit (import ../table-tree-marker.nix { }) requireNoTableTree;
in
{
  /*
    Serialize a value to compact libnftables JSON.

    `value` is a schema-shaped value, usually a ruleset
    (`{ nftables = [ … ]; }`). It is cleaned first, which drops unset
    nullable fields and module markers; it is not type-checked. A table
    tree, alone or among the commands, throws: wrap it in `dsl.ruleset`.

    Returns the JSON string.
  */
  toJson = value: builtins.toJSON (clean (requireNoTableTree "toJson" value));

  /*
    Render a value as pretty-printed Nix syntax for inspecting generated
    output.

    `value` is any schema-shaped value; it is cleaned the same way as in
    `toJson`.

    Returns a multi-line string from `lib.generators.toPretty`.
  */
  toNix =
    value: lib.generators.toPretty { multiline = true; } (clean (requireNoTableTree "toNix" value));
}
