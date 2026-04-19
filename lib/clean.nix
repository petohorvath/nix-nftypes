{ lib }:

# Recursively clean a Nix value for rendering:
#   - Drop null-valued attrs from multi-key attrsets (these are unset option defaults)
#   - Preserve { k = null; } where k is the only key (verdicts like accept/drop and
#     `{ ruleset = null; }` rely on null being significant there)
#   - Recurse into lists
#
# Both the JSON renderer (lib/json) and the text renderer (lib/text) call this
# once at their entry point so nested renderers trust their input is cleaned.

let
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
          (lib.filterAttrs (_: v': v' != null))
        ]
    else if builtins.isList v then
      map clean v
    else
      v;
in
clean
