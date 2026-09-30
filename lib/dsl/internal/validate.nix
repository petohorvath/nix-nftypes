/*
  Run a DSL-supplied body through `lib.evalModules` against a schema type.
  On schema violation, evalModules throws naming the option path; this is
  what makes silent-data-loss bugs surface as eval-time errors.

  Arguments:
    type    the schema type to check against.
    value   the body to validate.
    prefix  list of path components prepended to error-message paths, so
            callers can say where in the user's tree the failure happened
            (e.g. `[ "chains" "c" ]` → "chains.c.prio: not of type 'null or
            signed integer'").

  Returns the evaluated configuration, with option defaults filled in.

  Two cases:
    - submodule types (every body in lib/schema/objects.nix except
      `rulesetBody`): extract the inner options via `getSubOptions` and run
      evalModules directly against them, so errors show the field name
      without indirection.
    - other types (only `rulesetBody`, which is `oneOf [ nullLiteral,
      submodule { family; } ]`): wrap in a top-level `value` option. Errors
      look like "<prefix>.value: …"; rulesetBody is shallow enough that the
      indirection isn't burdensome.
*/
{ lib }:

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
  rawSubOptions = if type ? getSubOptions then type.getSubOptions [ ] else { };
  subOptions = removeAttrs rawSubOptions [ "_module" ];
  isFlatSubmodule = subOptions != { };
in
if isFlatSubmodule then
  (lib.evalModules {
    inherit prefix;
    modules = [
      { options = subOptions; }
      value
    ];
  }).config
else
  (lib.evalModules {
    inherit prefix;
    modules = [
      {
        options.value = lib.mkOption {
          inherit type;
          description = "Body validated against the requested schema type.";
        };
      }
      { inherit value; }
    ];
  }).config.value
