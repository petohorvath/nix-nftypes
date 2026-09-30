/*
  Render-time value cleaning shared by the JSON renderer (lib/json) and the
  text renderer (lib/text). Both call it once at their entry point so nested
  renderers can trust that their input is already clean.
*/
{ lib }:

let
  /*
    Recursively strip what must not reach rendered output. `v` is any Nix
    value. Returns `v` with these changes:
      - null-valued attributes of multi-key attrsets dropped (unset option
        defaults);
      - `_type` attributes of multi-key attrsets dropped. Libraries built on
        nftypes tag values with `_type = "<lib>.<kind>"` for boundary checks
        (matching nix-libnet's convention), and `nft -j -f` rejects unknown
        top-level keys;
      - `{ k = null; }` preserved where `k` is the only key, because verdicts
        like accept/drop and `{ ruleset = null; }` rely on that null;
      - lists cleaned element by element.
  */
  clean =
    v:
    if v == null then
      null
    else if builtins.isAttrs v then
      let
        names = builtins.attrNames v;
        singleKey = builtins.length names == 1;
        soleValue = v.${builtins.head names};
        keepExplicitNull = singleKey && soleValue == null;
      in
      if keepExplicitNull then
        v
      else
        lib.pipe v [
          (lib.mapAttrs (_: clean))
          (lib.filterAttrs (k: v': v' != null && k != "_type"))
        ]
    else if builtins.isList v then
      map clean v
    else
      v;
in
clean
