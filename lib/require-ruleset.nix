# The input check of `toJson`, `toText`, and `toTextPretty`, which take only
# a ruleset. Checking its shape is not validation (ADR 0003): the commands
# inside go unchecked.
{ lib }:

let
  inherit (import ./table-tree-marker.nix { }) isTableTree;

  # The keys a ruleset may have; cleaning strips a library's `_type` tag.
  rulesetKeys = [
    "_type"
    "nftables"
  ];

  describe =
    value:
    if builtins.isAttrs value then
      "an attribute set with ${lib.concatStringsSep ", " (builtins.attrNames value)}"
    else
      "a ${builtins.typeOf value}";
in
/*
  Guard a renderer's argument. `api` names the renderer in the error and
  `value` is its argument. Returns `value` unchanged when it is a ruleset,
  an attrset whose `nftables` list holds commands. Throws otherwise: for a
  table tree, alone or among the commands, it points to `dsl.ruleset`,
  which turns one into commands.
*/
api: value:
let
  fail = message: throw "nix-nftypes: ${api}: ${message}";
  isRuleset =
    builtins.isAttrs value
    && builtins.isList (value.nftables or null)
    && lib.subtractLists rulesetKeys (builtins.attrNames value) == [ ];
in
if isTableTree value || isRuleset && builtins.any isTableTree value.nftables then
  fail "got a dsl.table tree where a ruleset belongs; wrap it in dsl.ruleset [ … ]"
else if !isRuleset then
  fail "expected a ruleset { nftables = [ … ]; }, got ${describe value}; build one with dsl.ruleset [ … ]"
else
  value
