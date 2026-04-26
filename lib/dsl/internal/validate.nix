{ lib }:

# Run a DSL-supplied body through `lib.evalModules` against a schema type.
# On schema violation, evalModules throws naming the option path; this is
# what makes silent-data-loss bugs surface as eval-time errors.
#
# `prefix` is a list of path components prepended to error-message paths,
# so callers can say where in the user's tree the failure happened
# (e.g. `[ "chains" "c" ]` → "chains.c.prio: not of type 'null or signed
# integer'").
#
# Two cases:
#   - submodule types (every body in lib/schema/objects.nix except
#     `rulesetBody`): extract the inner options via `getSubOptions` and
#     run evalModules directly against them, so errors show the field
#     name without indirection.
#   - other types (only `rulesetBody`, which is `oneOf [ nullType,
#     submodule { family; } ]`): wrap in a top-level `value` option.
#     Errors look like "<prefix>.value: …"; rulesetBody is shallow enough
#     that the indirection isn't burdensome.

{
  type,
  value,
  prefix ? [ ],
}:

let
  # `getSubOptions` exists on submodules and on composite types like
  # `either`/`oneOf` that wrap them. Submodules return their declared
  # options (plus `_module`); composites return an empty set unless the
  # composite happens to be a single submodule. Distinguish by whether
  # any user-declared option survives the `_module` strip.
  rawSubOpts = if type ? getSubOptions then type.getSubOptions [ ] else { };
  subOpts = builtins.removeAttrs rawSubOpts [ "_module" ];
  isFlatSubmodule = subOpts != { };
in
if isFlatSubmodule then
  (lib.evalModules {
    inherit prefix;
    modules = [
      { options = subOpts; }
      value
    ];
  }).config
else
  (lib.evalModules {
    inherit prefix;
    modules = [
      { options.value = lib.mkOption { inherit type; }; }
      { value = value; }
    ];
  }).config.value
