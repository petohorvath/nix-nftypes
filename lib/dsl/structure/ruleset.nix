/*
  Ruleset envelope. For command builders (add, create, delete, destroy,
  flush, list, rename, reset, replace, insert) see ./commands.nix. The
  ruleset renderer passes any bare command attrset through unchanged, so
  users can always drop to raw JSON if needed.
*/
{
  expandTable,
  lib,
  resetOrder,
}:

let
  inherit (import ../../ruleset-shape.nix { }) isRuleset;
  inherit (import ../../table-tree-marker.nix { }) isTableTree;

  inherit (import ../../describe.nix { inherit lib; }) describe;
  fail = import ../../fail.nix { } "dsl.ruleset";

  # Table preparation belongs to the table module. The ruleset only knows
  # how to combine tables, rulesets, nested lists, and the raw-command
  # escape hatch. A ruleset's commands are spliced in place, since nft
  # rejects a ruleset nested inside another.
  flattenChild =
    child:
    if isTableTree child then
      expandTable child
    else if isRuleset child then
      flattenChildren child.nftables
    else if builtins.isList child then
      flattenChildren child
    else if builtins.isFunction child || child ? __functor then
      fail "invalid child: expected a Table tree, ruleset, command attrset, or list, got a function, such as a builder not yet called; call it, as in `flush.ruleset { }`"
    # A command's values are bodies, so one holding a function is a
    # namespace of builders, such as `dsl.flush`.
    else if builtins.isAttrs child && lib.any builtins.isFunction (builtins.attrValues child) then
      fail "invalid child: expected a Table tree, ruleset, command attrset, or list, got a namespace of builders with ${lib.concatStringsSep ", " (builtins.attrNames child)}; call one of them, as in `flush.ruleset { }`"
    else if builtins.isAttrs child then
      [ child ]
    else
      fail "invalid child: expected a Table tree, ruleset, command attrset, or list, got ${describe child}";

  flattenChildren = children: lib.concatMap flattenChild children;
in
{
  /*
    Assemble the top-level ruleset envelope. `children` is a list of Table
    trees (expanded into their commands), rulesets (their commands spliced
    in place), bare command attrsets (passed through unvalidated), or
    nested lists of these. Returns `{ nftables = [ commands ]; }` and
    throws for a non-list `children` or any other child.

    It also throws when a reset of a counter, quota, set, map, or rule is
    not the last command, built or raw: nft runs one only there, and
    anywhere else resets nothing yet still exits 0.
  */
  ruleset =
    children:
    let
      commands =
        if builtins.isList children then
          flattenChildren children
        else
          fail "expected a list of children, got ${describe children}; wrap it in a list: dsl.ruleset [ … ]";
    in
    {
      nftables =
        if resetOrder.isRunAsWritten commands then
          commands
        else
          fail "a reset of a ${resetOrder.kindsText} must be the last command; nft resets nothing for one placed earlier";
    };
}
