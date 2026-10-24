/*
  DSL-key → JSON-key rename maps, per-tag.

  User-facing DSL attribute names are translated to the JSON key names that
  nftables expects. Two kinds of rename apply:

    1. camelCase → hyphenated or underscored JSON keys (`queueThreshold`
       → `queue-threshold`, `gcInterval` → `gc-interval`, `rateUnit` →
       `rate_unit`, `typeFlags` → `type_flags`, `newName` → `newname`, …).
       Every DSL key is camelCase, whatever separator the JSON key uses.
    2. DSL-idiom renames where the JSON key is inconsistent with the
       library's plural-for-lists convention (`elements` → `elem`,
       `statements` → `expr` or `stmt`) or abbreviates a word
       (`statement` → `stmt`). These are deliberate divergences from the
       JSON spec — chosen so that list-valued body keys match the rest of
       the DSL (`rules`, `flags`, `chains`, `sets`, …), and so that a
       rule's statements don't read like the `dsl.expr` namespace.

  Each DSL body takes one spelling of each field (ADR 0009): a JSON
  spelling throws, pointing to the DSL name, so the DSL spelling never
  leaks into evalModules and the JSON spelling never leaks into user code.

  Builders and table preparation call the per-tag rename function on the
  user's arguments before handing them to the schema. Each function takes
  the body's location (./location.nix), such as a table tree's `sets.s`,
  for its errors, then the body. A statement builder, whose argument
  pattern names the DSL spellings, calls `checkSpelling.<tag>` first, so
  a JSON spelling throws pointing to its DSL name rather than failing the
  pattern as an unexpected argument.
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;

  renames = {
    log = {
      queueThreshold = "queue-threshold";
    };

    # Shared by the limit statement and the named limit object.
    limit = {
      rateUnit = "rate_unit";
      burstUnit = "burst_unit";
    };

    quota = {
      valUnit = "val_unit";
      usedUnit = "used_unit";
    };

    nat = {
      typeFlags = "type_flags";
    };

    /*
      Shared by named-set and named-map bodies. The JSON schema
      (parser_json.c) uses the singular `elem` whether the value is one
      element or a list, and the singular `stmt` for a list of statements;
      the DSL names both lists in the plural.
    */
    set = {
      gcInterval = "gc-interval";
      autoMerge = "auto-merge";
      elements = "elem";
      statements = "stmt";
    };

    # The standalone `element` object kind, which adds elements to an
    # existing set or map.
    element = {
      elements = "elem";
    };

    # A rule's statement list, in a rule command and a table-tree rule
    # entry. `expr` would read like the `dsl.expr` namespace.
    rule = {
      statements = "expr";
    };

    renameChain = {
      newName = "newname";
    };

    # Shared by the `setStmt` and `mapStmt` statements.
    setStmt = {
      statements = "stmt";
    };

    # `meter` applies one statement, not a list.
    meter = {
      statement = "stmt";
    };
  };

  /*
    Throw when `attrs` gives a field by its JSON spelling in `renames`, a
    { dslName = "jsonName"; } map, naming the DSL spelling to write.
    Returns `attrs` unchanged otherwise, and a value that isn't an attrset
    too, for the schema to reject.
  */
  checkKeys =
    renames: location: attrs:
    let
      jsonSpellings = builtins.filter (dslName: attrs ? ${renames.${dslName}}) (
        builtins.attrNames renames
      );
      dslName = builtins.head jsonSpellings;
    in
    if builtins.isAttrs attrs && jsonSpellings != [ ] then
      fail (within location [
        renames.${dslName}
      ]) "is the JSON spelling; write `${dslName}`"
    else
      attrs;

  # Check `attrs`, then rename its DSL keys to their JSON keys. Keys not in
  # `renames` pass through unchanged.
  renameKeys =
    renames: location: attrs:
    let
      checked = checkKeys renames location attrs;
    in
    if builtins.isAttrs checked then
      lib.mapAttrs' (k: v: lib.nameValuePair (renames.${k} or k) v) checked
    else
      checked;
in
lib.mapAttrs (_: renameKeys) renames
// {
  # For a body without DSL-only spellings.
  none = _location: lib.id;

  checkSpelling = lib.mapAttrs (_: checkKeys) renames;
}
