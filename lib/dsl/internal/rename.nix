/*
  DSL-key → JSON-key rename maps, per body, and the check that each body
  takes one spelling of each field (ADR 0009).

  User-facing DSL attribute names are translated to the JSON key names that
  nftables expects. Two kinds of rename apply:

    1. camelCase → hyphenated or underscored JSON keys (`queueThreshold`
       → `queue-threshold`, `gcInterval` → `gc-interval`, `rateUnit` →
       `rate_unit`, `typeFlags` → `type_flags`, `newName` → `newname`, …).
       Every DSL key is camelCase, whatever separator the JSON key uses.
    2. The field-word rule (ADR 0009): a field that holds statements,
       elements, or a key takes the DSL word for what it holds, whatever
       the JSON key is (`elements` → `elem`, `element` and `key` → `elem`
       in `setStmt` and `mapStmt`, `statements` → `expr` or `stmt`,
       `statement` → `stmt`), and a field whose JSON key names something
       other than what it holds takes the DSL word (`code` → `expr` in
       `reject`, `dataType` → `map` in a map body). These are deliberate
       divergences from the JSON spec, so that a field's name says what
       it holds and a rule's statements don't read like the `dsl.expr`
       namespace.

  A JSON spelling throws, pointing to the DSL name, so the DSL spelling
  never leaks into evalModules and the JSON spelling never leaks into user
  code.

  - `<body> location attrs`, for `set`, `map`, `element`, `limit`, `rule`,
    and `renameChain`: check `attrs`, then rename its DSL keys to their JSON
    keys. `location` is the body's location (./location.nix), such as a
    table tree's `sets.s`, for its errors. Keys without a rename pass
    through unchanged.
  - `none location attrs`: `attrs`, for a body without DSL-only spellings.
  - `quotaObject location attrs`: `attrs`, for a quota object's body. Its
    `val`, the quota statement's word, throws and points to `bytes`.
  - `checkSpelling.rule location attrs`: the check alone, for a rule body,
    which ./rule-body.nix checks further before renaming it.
  - `statement name location attrs`: check and rename the body of the
    statement builder `dsl.<name>`, such as `log` or `snat`
    (./builder.nix). A builder without renames takes `attrs` unchanged.
  - `dslKey body jsonKey`: the DSL name of the JSON key `jsonKey` in
    `body`, such as `elements` for an `element`'s `elem`, or `jsonKey`
    when it has no rename.
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;

  # `snat` and `dnat` take the full NAT body.
  natRenames = {
    typeFlags = "type_flags";
  };

  /*
    Shared by named-set and named-map bodies. The JSON schema
    (parser_json.c) uses the singular `elem` whether the value is one
    element or a list, and the singular `stmt` for a list of statements;
    the DSL names both lists in the plural.
  */
  setRenames = {
    gcInterval = "gc-interval";
    autoMerge = "auto-merge";
    elements = "elem";
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

    set = setRenames;

    # A map's JSON `map` holds the data type of its values.
    map = setRenames // {
      dataType = "map";
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

    # `setStmt` and `mapStmt` apply a list of statements to the element.
    # The JSON `elem` holds the element of a set and the key of a map.
    setStmt = {
      element = "elem";
      statements = "stmt";
    };
    mapStmt = {
      key = "elem";
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

  none = _location: lib.id;

  # The quota statement takes its threshold in `val`, a quota object in
  # `bytes`.
  quotaObject =
    location: attrs:
    if builtins.isAttrs attrs && attrs ? val then
      fail (within location [
        "val"
      ]) "is the quota statement's spelling; a quota object takes its threshold in `bytes`"
    else
      attrs;
in
{
  inherit (bodyRenames)
    element
    limit
    map
    renameChain
    rule
    set
    ;

  inherit none quotaObject;

  dslKey =
    body: jsonKey:
    let
      dslKeys = lib.mapAttrs' (dslName: jsonName: lib.nameValuePair jsonName dslName) renames.${body};
    in
    dslKeys.${jsonKey} or jsonKey;

  checkSpelling.rule = checkKeys renames.rule;

  statement = name: bodyRenames.${name} or none;
}
