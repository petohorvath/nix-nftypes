/*
  Ruleset envelope. For command builders (add, create, delete, destroy,
  flush, list, rename, reset, replace, insert) see ./commands.nix. The
  ruleset renderer passes any bare command attrset through unchanged, so
  users can always drop to raw JSON if needed.
*/
{ expandTable, lib }:

let
  markers = import ../internal/markers.nix { };

  # Table preparation belongs to the table module. The ruleset only knows
  # how to combine tables, nested lists, and the raw-command escape hatch.
  flattenChild =
    child:
    if builtins.isAttrs child && (child.${markers.table} or false) then
      expandTable child
    else if builtins.isList child then
      flattenChildren child
    else if builtins.isAttrs child then
      [ child ]
    else
      throw "nix-nftypes: dsl.ruleset: invalid child — expected table node, command attrset, or list";

  flattenChildren = children: lib.concatMap flattenChild children;
in
{
  /*
    Assemble the top-level ruleset envelope. `children` is a list of table
    nodes (expanded into their commands), bare command attrsets (passed
    through unvalidated), or nested lists of either. Returns
    `{ nftables = [ commands ]; }` and throws on any other child.
  */
  ruleset = children: {
    nftables = flattenChildren children;
  };
}
