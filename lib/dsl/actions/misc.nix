/*
  Statements that do not fit the variant-namespace pattern: mangle
  (payload-field rewrite), dynamic set/map modification (setStmt, mapStmt),
  resetStmt (takes a bare expression), secmark/tunnel (`.ref` to a named
  object), and xt (xtables bridge).
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };

  # The pattern names the DSL spellings; `setStmt` and `mapStmt` check for
  # a JSON spelling first, so it throws pointing to its DSL name.
  setStmtInline =
    {
      op,
      elem,
      set,
      statements ? null,
    }:
    {
      set = compact {
        inherit op elem;
        stmt = statements;
        set = reference.atReference "setStmt" set;
      };
    };

  mapStmtInline =
    {
      op,
      elem,
      data,
      map,
      statements ? null,
    }:
    {
      map = compact {
        inherit
          op
          elem
          data
          ;
        stmt = statements;
        map = reference.atReference "mapStmt" map;
      };
    };
in
{
  /*
    Rewrite a packet field. `key` is the field expression to overwrite and
    `value` the new value expression. Returns a mangle statement.
  */
  mangle = key: value: { mangle = { inherit key value; }; };

  /*
    Modify a named set from the packet path. Distinct from the anonymous set
    expression in exprs.nix. `op` is `"add"`, `"update"`, or `"delete"`,
    `elem` the element expression, `set` the set name with or without its
    leading `@`, and `statements` an optional statement list. Returns a set
    statement referencing `"@<name>"`; throws when `set` is not a string,
    and for `stmt`, pointing to `statements`.
  */
  setStmt = args: setStmtInline (rename.checkSpelling.setStmt (location.builder [ "setStmt" ]) args);

  /*
    Modify a named map from the packet path. Distinct from the map lookup
    expression in exprs.nix. `op` is the update operation, `elem` the key
    expression, `data` the value expression, `map` the map name with or
    without its leading `@`, and `statements` an optional statement list.
    Returns a map statement referencing `"@<name>"`; throws when `map` is
    not a string, and for `stmt`, pointing to `statements`.
  */
  mapStmt = args: mapStmtInline (rename.checkSpelling.setStmt (location.builder [ "mapStmt" ]) args);

  /*
    Reset stateful data referenced by an expression, such as a TCP option.
    `e` is that expression. Named like `setStmt`, since `reset` is the
    command namespace. Returns a reset statement.
  */
  resetStmt = e: { reset = e; };

  /*
    Apply a security mark. `secmark.ref ref` names the secmark object:
    `ref` is its name, with or without a leading `@`, or a map expression
    that selects one by key. Returns a secmark statement.
  */
  secmark = reference.referenceOnly "secmark" "secmark";

  /*
    Attach tunnel metadata. `tunnel.ref ref` names the tunnel object, as
    `secmark.ref` does. Returns a tunnel statement.
  */
  tunnel = reference.referenceOnly "tunnel" "tunnel";

  /*
    Represent an xtables extension for read-back compatibility; nftables
    rejects it as JSON input. `type` is the extension type and `name` its
    name. Returns an xt statement.
  */
  xt = type: name: { xt = { inherit type name; }; };
}
