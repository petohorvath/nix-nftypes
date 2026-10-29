/*
  How an error names a value the caller passed where another belongs, such
  as `a Table tree`, `a ruleset`, `an attribute set with add`, or
  `a string`, so that every "got …" in an error reads the same way.
*/
{ lib }:

let
  inherit (import ./ruleset-shape.nix { }) isRuleset;
  inherit (import ./table-tree-marker.nix { }) isTableTree;
in
{
  describe =
    value:
    if isTableTree value then
      "a Table tree"
    else if isRuleset value then
      "a ruleset"
    else if value == { } then
      "an empty attribute set"
    else if builtins.isAttrs value then
      "an attribute set with ${lib.concatStringsSep ", " (builtins.attrNames value)}"
    else if builtins.isFunction value then
      "a function"
    else if value == null then
      "null"
    else if builtins.isInt value then
      "an int"
    else
      "a ${builtins.typeOf value}";
}
