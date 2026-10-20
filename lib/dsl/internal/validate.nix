/*
  Run a DSL-supplied body through `lib.evalModules` against a schema type.
  On schema violation, evalModules throws naming the option path; this is
  what makes silent-data-loss bugs surface as eval-time errors.

  Arguments:
    type      the schema type to check against.
    value     the body to validate.
    location  where the body is (./location.nix), so errors say where in
              the user's call the failure happened: the module system's
              option paths start with its `optionPrefix` (`chains.c.prio`,
              `dsl.create.chain.prio`), and this module's own errors with
              `nix-nftypes: <api>: `.

  Returns the evaluated configuration, with option defaults filled in.

  `value` is data, never a module (see ./require-body.nix): a string such
  as `"c1"` or `"/sp1"` is not imported as a module file, and module keys
  such as `imports`, `key`, or `freeformType` are fields the schema doesn't
  have. Each throws an error naming its path.

  Two cases:
    - submodule types (every body in lib/schema/objects.nix except
      `flushRulesetBody`): extract the inner options via `getSubOptions` and run
      evalModules directly against them, so errors show the field name
      without indirection. The options alone drop a check on the body as
      a whole (a `discriminatedSubmodule` constraint such as a chain's
      type, hook and prio together), so the type's own check runs too.
    - other types (only `flushRulesetBody`, which is `oneOf [ nullLiteral,
      submodule { family; } ]`): wrap in a top-level `value` option. Errors
      look like "<prefix>.value: …"; flushRulesetBody is shallow enough that the
      indirection isn't burdensome.
*/
{ lib }:

{
  type,
  value,
  location,
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
  requireBody = import ./require-body.nix { inherit lib; };
  inherit (import ./location.nix { inherit lib; }) fail;
  body = requireBody location value;
  prefix = location.optionPrefix;
in
if isFlatSubmodule then
  let
    inherit
      (lib.evalModules {
        inherit prefix;
        modules = [
          { options = subOptions; }
          # `config` keeps module keys such as `imports` plain fields.
          { config = body; }
        ];
      })
      config
      ;
  in
  if type.check body then
    config
  else
    # A field's own type error names the field, so it goes first.
    builtins.seq (lib.foldl' (forced: name: builtins.seq (config.${name} or null) forced) null (
      builtins.attrNames body
    )) (fail location "not of type `${type.description}'.")
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
