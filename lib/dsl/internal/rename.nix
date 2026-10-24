/*
  DSL-key → JSON-key rename maps, per body, and the check that each body
  takes one spelling of each field (ADR 0009).

  User-facing DSL attribute names are translated to the JSON key names that
  nftables expects. Two kinds of rename apply:

    1. camelCase → hyphenated or underscored JSON keys (`queueThreshold`
       → `queue-threshold`, `gcInterval` → `gc-interval`, `rateUnit` →
       `rate_unit`, `typeFlags` → `type_flags`, `newName` → `newname`, …).
       Every DSL key is camelCase, whatever separator the JSON key uses.
    2. DSL-idiom renames where the JSON key names a list of elements or
       statements in the singular (`elements` → `elem`, `statements` →
       `expr` or `stmt`), abbreviates a word (`statement` → `stmt`), or
       names something other than what it holds (`code` → `expr` in `reject`).
       These are deliberate divergences from the JSON spec — chosen so
       that list-valued body keys match the rest of the DSL (`rules`,
       `flags`, `chains`, `sets`, …), and so that a rule's statements
       don't read like the `dsl.expr` namespace.

  A JSON spelling throws, pointing to the DSL name, so the DSL spelling
  never leaks into evalModules and the JSON spelling never leaks into user
  code.

  - `<body> location attrs`, for `set`, `element`, `limit`, `rule`, and
    `renameChain`: check `attrs`, then rename its DSL keys to their JSON
    keys. `location` is the body's location (./location.nix), such as a
    table tree's `sets.s`, for its errors. Keys without a rename pass
    through unchanged.
  - `none location attrs`: `attrs`, for a body without DSL-only spellings.
  - `checkSpelling.rule location attrs`: the check alone, for a rule body,
    which ./rule-body.nix checks further before renaming it.
  - `statement name location attrs`: check and rename the body of the
    statement builder `dsl.<name>`, such as `log` or `snat`
    (./statement.nix). A builder without renames takes `attrs` unchanged.
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;

  # `snat` and `dnat` take the full NAT body.
  natRenames = {
    typeFlags = "type_flags";
  };

  # `setStmt` and `mapStmt` apply a list of statements to the element.
  elementStatementRenames = {
    statements = "stmt";
  };

  # By body: a statement builder's name, an object kind, or `rule`.
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

    snat = natRenames;
    dnat = natRenames;

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

    # The JSON `expr` holds the ICMP code, not an expression.
    reject = {
      code = "expr";
    };

    setStmt = elementStatementRenames;
    mapStmt = elementStatementRenames;

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

  # Rename the DSL keys of the checked `attrs` to their JSON keys. Keys not
  # in `renames` pass through unchanged.
  renameChecked = renames: lib.mapAttrs' (k: v: lib.nameValuePair (renames.${k} or k) v);

  # Check `attrs`, then rename it.
  renameKeys =
    renames: location: attrs:
    let
      checked = checkKeys renames location attrs;
    in
    if builtins.isAttrs checked then renameChecked renames checked else checked;

  bodyRenames = lib.mapAttrs (_: renameKeys) renames;
in
{
  inherit (bodyRenames)
    element
    limit
    renameChain
    rule
    set
    ;

  none = _location: lib.id;

  checkSpelling.rule = checkKeys renames.rule;

  statement = name: renameKeys (renames.${name} or { });
}
