/*
  The input step `toJson`, `toText`, and `toTextPretty` share, which takes
  only a ruleset. None of its parts is validation (ADR 0003): the commands
  inside go unchecked.

  - Its shape is checked: an attrset with just an `nftables` list, and no
    module property such as `lib.mkIf` anywhere (./module-property.nix).
  - It is cleaned (./clean.nix).
  - A rule body without `expr`, listed or under a command verb, gets
    `expr = [ ]`. nft's JSON parser requires the key on every rule but a
    deleted one, a destroyed rule included, though it ignores a selected
    rule's `expr`. `validate` and the command builders return only the
    fields given, so without this part a raw `destroy.rule` would load as
    text but not as JSON.
*/
{ lib, clean }:

let
  inherit (import ./ruleset-shape.nix { }) isRuleset;
  inherit (import ./table-tree-marker.nix { }) isTableTree;
  inherit (import ./describe.nix { inherit lib; }) describe;
  fail = import ./fail.nix { };
  inherit (import ./module-property.nix { inherit lib; }) findModuleProperty modulePropertyMessage;

  withExpr = body: if builtins.isAttrs body && !(body ? expr) then body // { expr = [ ]; } else body;

  # A listed rule is `{ rule = body; }`, a rule command
  # `{ <verb> = { rule = body; }; }`.
  fillRuleExpr =
    entry:
    if !(builtins.isAttrs entry) then
      entry
    else if entry ? rule then
      entry // { rule = withExpr entry.rule; }
    else
      lib.mapAttrs (
        _: wrapped:
        if builtins.isAttrs wrapped && wrapped ? rule then
          wrapped // { rule = withExpr wrapped.rule; }
        else
          wrapped
      ) entry;
in
/*
  Prepare a renderer's argument. `api` names the renderer in the error and
  `value` is its argument. Returns the cleaned ruleset, each rule body with
  an `expr`, when `value` is a ruleset, an attrset whose `nftables` list
  holds commands. Throws otherwise: for a table tree, alone or among the
  commands, it points to `dsl.ruleset`, which turns one into commands, and
  for a raw `nftables` command, which nft rejects, to `dsl.ruleset`, which
  splices a ruleset's commands in place.
*/
api: value:
if isTableTree value || isRuleset value && builtins.any isTableTree value.nftables then
  fail api "got a Table tree where a ruleset belongs; wrap it in dsl.ruleset [ … ]"
else if !(isRuleset value) then
  fail api "expected a ruleset { nftables = [ … ]; }, got ${describe value}; build one with dsl.ruleset [ … ]"
else if builtins.any (command: builtins.isAttrs command && command ? nftables) value.nftables then
  fail api "got a ruleset { nftables = [ … ]; } nested among a ruleset's commands, which nft rejects; splice it in with dsl.ruleset [ … ]"
else if findModuleProperty value != null then
  let
    found = findModuleProperty value;
  in
  fail api "${lib.concatStringsSep "." found.path}: ${modulePropertyMessage found}"
else
  let
    cleaned = clean value;
  in
  cleaned // { nftables = map fillRuleExpr cleaned.nftables; }
