/*
  Statements that do not fit the variant-namespace pattern: mangle
  (payload-field rewrite), dynamic set/map modification (setStmt, mapStmt),
  reset/secmark/tunnel (each takes a bare expression), xt (xtables bridge),
  and last / lastUsed.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
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
    `elem` the element expression, `set` the set reference, and `stmt` an
    optional statement list. Returns a set statement.
  */
  setStmt =
    {
      op,
      elem,
      set,
      stmt ? null,
    }:
    {
      set = compact {
        inherit
          op
          elem
          set
          stmt
          ;
      };
    };

  /*
    Modify a named map from the packet path. Distinct from the map lookup
    expression in exprs.nix. `op` is the update operation, `elem` the key
    expression, `data` the value expression, `map` the map reference, and
    `stmt` an optional statement list. Returns a map statement.
  */
  mapStmt =
    {
      op,
      elem,
      data,
      map,
      stmt ? null,
    }:
    {
      map = compact {
        inherit
          op
          elem
          data
          map
          stmt
          ;
      };
    };

  /*
    Reset stateful data referenced by an expression, such as a TCP option.
    `e` is that expression. Returns a reset statement.
  */
  reset = e: { reset = e; };

  /*
    Apply a security mark. `e` is the secmark expression, typically a named
    object reference. Returns a secmark statement.
  */
  secmark = e: { secmark = e; };

  /*
    Attach tunnel metadata. `e` is the tunnel expression, typically a named
    object reference. Returns a tunnel statement.
  */
  tunnel = e: { tunnel = e; };

  /*
    Represent an xtables extension for read-back compatibility; nftables
    rejects it as JSON input. `type` is the extension type and `name` its
    name. Returns an xt statement.
  */
  xt = type: name: { xt = { inherit type name; }; };

  # `last` is a bare value and `lastUsed` the `{ used = …; }` form. They stay
  # separate because `{ last = null; }` cannot also expose sub-attributes.
  last = {
    last = null;
  };

  /*
    Record when the rule last matched, seeded with a previous value. `used`
    is the last-used time. Returns `{ last = { used; }; }`.
  */
  lastUsed = used: {
    last = {
      inherit used;
    };
  };
}
