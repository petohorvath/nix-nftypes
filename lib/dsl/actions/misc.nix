{ lib }:

# Miscellaneous statements that don't fit the variant-namespace pattern:
# mangle (payload-field rewrite), dynamic set/map modification (setStmt,
# mapStmt), reset/secmark/tunnel (each takes a bare expression), xt
# (xtables bridge), and last / lastUsed.

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  mangle = key: value: { mangle = { inherit key value; }; };

  # Dynamic set/map modification (distinct from the anonymous set expression
  # and the map-lookup expression in exprs.nix).
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

  reset = e: { reset = e; };
  secmark = e: { secmark = e; };
  tunnel = e: { tunnel = e; };

  xt = type: name: { xt = { inherit type name; }; };

  # `last` is a bare value; `lastUsed t` is the {used = t} form. Kept separate
  # because a single-key attrset `{ last = null; }` can't also expose sub-attrs.
  last = {
    last = null;
  };
  lastUsed = t: {
    last = {
      used = t;
    };
  };
}
