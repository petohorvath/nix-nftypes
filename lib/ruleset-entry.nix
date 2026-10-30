/*
  The shape of one entry of a ruleset's `nftables` list: a command, one
  verb holding one object kind, or a bare listed object, one Read-back tag.
  nft's JSON parser runs only the first verb of an entry with several, and
  only the first kind under a verb, yet exits 0, so `{ add = { table = …;
  chain = …; }; }` loaded the table alone. It rejects a statement, a Table
  tree's body, and an empty attrset as an entry.

  This checks the shape, not the bodies (ADR 0003): a kind under a verb is
  not checked against the kinds the schema models, so a raw command stays
  an escape hatch for a parser-valid form the schema leaves out.

  `verbs` are the command verbs and `readBackTags` the tags of a listed
  object, both from the schema.
*/
{
  lib,
  readBackTags,
  verbs,
}:

let
  inherit (import ./describe.nix { inherit lib; }) describe;

  # Cleaning strips a library's `_type` marker before nft sees a value.
  unmarked = value: if builtins.isAttrs value then removeAttrs value [ "_type" ] else value;

  names = value: lib.concatStringsSep ", " (builtins.attrNames value);
in
{
  # Why `entry` is no ruleset entry, as an error message without its
  # location, or `null` when it is one.
  entryProblem =
    marked:
    let
      entry = unmarked marked;
      keys = builtins.attrNames entry;
      key = builtins.head keys;
      kinds = unmarked entry.${key};
    in
    if entry == { } then
      "got an empty attribute set, which nft rejects; leave the entry out, as with lib.optional"
    else if !(builtins.isAttrs entry) then
      "expected a command or a listed object, got ${describe entry}"
    else if builtins.length keys > 1 then
      "holds ${names entry}, but nft runs only the first; give each command or listed object its own entry"
    else if builtins.elem key verbs then
      if !(builtins.isAttrs kinds) || kinds == { } then
        "`${key}` takes one object kind, such as `${key}.table`, got ${describe kinds}"
      else if builtins.length (builtins.attrNames kinds) > 1 then
        "`${key}` holds ${names kinds}, but nft runs only the first; give each its own command"
      else
        null
    else if builtins.elem key readBackTags then
      null
    else
      "expected a command, a verb such as `add` holding one object kind, or a listed object, such as `table`, got ${describe entry}";
}
