/*
  How an error names a value the caller passed where another belongs, so
  that every "got …" in an error reads the same way.

  - `isRuleset value`: whether `value` has a ruleset's shape, an attrset
    with just an `nftables` list. A library's `_type` tag may sit beside
    it; cleaning strips it.
  - `describe value`: a phrase naming what `value` is, such as
    `a Table tree`, `a ruleset`, `an attribute set with add`, or
    `a string`.
*/
{ lib }:

let
  inherit (import ./table-tree-marker.nix { }) isTableTree;

  rulesetKeys = [
    "_type"
    "nftables"
  ];

  isRuleset =
    value:
    builtins.isAttrs value
    && builtins.isList (value.nftables or null)
    && lib.subtractLists rulesetKeys (builtins.attrNames value) == [ ];
in
{
  inherit isRuleset;

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
    else
      "a ${builtins.typeOf value}";
}
