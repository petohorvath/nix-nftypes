{ lib }:

let
  # Recursively clean a Nix value for JSON output:
  #   - Drop null-valued attrs from multi-key attrsets (these are unset option defaults)
  #   - Preserve { k = null; } where k is the only key (verdicts like accept/drop and
  #     `{ ruleset = null; }` rely on null being significant there)
  #   - Recurse into lists
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

  toJSON = value: builtins.toJSON (clean value);

  # Pretty-printed rendering via nix's builtin — useful for reading generated output.
  # We round-trip through toJSON to apply the same cleaning, then re-parse.
  toPretty = value: lib.generators.toPretty { multiline = true; } (clean value);
in
{
  inherit clean toJSON toPretty;
}
