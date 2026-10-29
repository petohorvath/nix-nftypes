/*
  Statements that do not fit the variant-namespace pattern: mangle
  (payload-field rewrite), dynamic set/map modification (setStmt, mapStmt),
  resetStmt (takes a bare expression), secmark/tunnel (`.ref` to a named
  object), and notrack (no body).
*/
{ lib, statement }:

let
  reference = import ../internal/reference.nix { inherit lib; };
in
{
  /*
    Rewrite a packet field. `key` is the field expression to overwrite and
    `value` the new value expression. Returns a mangle statement, and
    throws when its body doesn't validate.
  */
  mangle = key: value: statement.tagged { name = "mangle"; } { inherit key value; };

  /*
    Modify a named set from the packet path. Distinct from the anonymous set
    expression in exprs.nix.

    `setStmt { op; element; set; statements?; }` takes the operation,
    `"add"`, `"update"`, or `"delete"`, the element expression `element`,
    the set name `set` with or without its leading `@`, and an optional
    statement list. Returns a set statement referencing `"@<name>"`. Throws
    when the body doesn't validate, when `set` is not a string, and for the
    JSON spellings `elem` and `stmt`, pointing to `element` and
    `statements`.
  */
  setStmt = statement.fromFields {
    name = "setStmt";
    tag = "set";
    prepare = reference.normaliseAtReference "set";
  };

  /*
    Modify a named map from the packet path. Distinct from the map lookup
    expression in exprs.nix.

    `mapStmt { op; key; data; map; statements?; }` takes the update
    operation, the key expression `key`, the value expression `data`, the
    map name `map` with or without its leading `@`, and an optional
    statement list. Returns a map statement referencing `"@<name>"`. Throws
    when the body doesn't validate, when `map` is not a string, and for the
    JSON spellings `elem` and `stmt`, pointing to `key` and `statements`.
  */
  mapStmt = statement.fromFields {
    name = "mapStmt";
    tag = "map";
    prepare = reference.normaliseAtReference "map";
  };

  /*
    Reset stateful data referenced by an expression, such as a TCP option.
    `e` is that expression. Named like `setStmt`, since `reset` is the
    command namespace. Returns a reset statement, and throws when `e` is
    not an expression.
  */
  resetStmt = statement.tagged {
    name = "resetStmt";
    tag = "reset";
  };

  /*
    Apply a security mark. `secmark.ref ref` names the secmark object:
    `ref` is its name, with or without a leading `@`, or a map expression
    that selects one by key. Returns a secmark statement.
  */
  secmark = statement.referenceOnly { name = "secmark"; };

  /*
    Attach tunnel metadata. `tunnel.ref ref` names the tunnel object, as
    `secmark.ref` does. Returns a tunnel statement.
  */
  tunnel = statement.referenceOnly { name = "tunnel"; };

  # Exempt the packet from connection tracking. A statement, not a verdict:
  # it doesn't end the rule.
  notrack = {
    notrack = null;
  };
}
