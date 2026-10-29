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

  Returns `value` unchanged once the check has run in full, as the public
  `validate` (../../validate.nix) does, for the reasons it gives: a body
  holds only the fields its caller gave.

  `value` is data, never a module (see ./require-body.nix): a string such
  as `"c1"` or `"/sp1"` is not imported as a module file, and module keys
  such as `imports`, `key`, or `freeformType` are fields the schema doesn't
  have. Each throws an error naming its path.

  A union such as `flushRulesetBody`, `oneOf [ nullLiteral, submodule {
  family; } ]`, or a statement's `logBody`, is checked against the branch
  the module system merges `value` with (`branchFor`). Then two cases:
    - submodule types (every body in lib/schema/objects.nix, and the
      branch an attrset takes in such a union): extract the inner options
      via `getSubOptions` and run evalModules directly against them, so
      errors show the field name without indirection, as in
      `dsl.flush.ruleset.family` or `dsl.log.level`. The options alone drop
      a check on the body as a whole (a `discriminatedSubmodule` constraint
      such as a chain's type, hook and prio together), so the type's own
      check runs too, once every field has been checked: its error,
      "<prefix>: not of type `<description>'", names the rule the type's
      description states.
    - other types, such as `nullLiteral` or an expression: wrap in a
      top-level `value` option. Errors look like "<prefix>.value: …", as in
      `dsl.resetStmt.value`.
*/
{ lib }:

{
  type,
  value,
  location,
}:

let
  /*
    The submodule branch of the union `type` that the module system merges
    `value` with, or `type` itself when that branch is no submodule: an
    `either` takes its left type when `value` passes that type's check, and
    its right one otherwise.
  */
  branchFor =
    type: value:
    let
      inherit (type.nestedTypes) left right;
      branch = branchFor (if left.check value then left else right) value;
    in
    if type.name == "either" && branch.name == "submodule" then branch else type;

  target = branchFor type value;

  # `getSubOptions` exists on submodules and on composite types like
  # `either`/`oneOf` that wrap them. Submodules return their declared
  # options (plus `_module`); composites return an empty set unless the
  # composite happens to be a single submodule. Distinguish by whether
  # any user-declared option survives the `_module` strip.
  rawSubOptions = if target ? getSubOptions then target.getSubOptions [ ] else { };
  subOptions = removeAttrs rawSubOptions [ "_module" ];
  isFlatSubmodule = subOptions != { };
  requireBody = import ./require-body.nix { inherit lib; };
  inherit (import ./location.nix { inherit lib; }) fail;
  body = requireBody location value;
  prefix = location.optionPrefix;
  checked =
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
      if target.check body then
        config
      else
        # A field's own error names the field, so it goes first: an
        # unknown field, a wrong value, or a missing required field.
        builtins.deepSeq (removeAttrs config [ "_module" ]) (
          fail location "not of type `${target.description}'."
        )
    else
      (lib.evalModules {
        inherit prefix;
        modules = [
          {
            options.value = lib.mkOption {
              type = target;
              description = "Body validated against the requested schema type.";
            };
          }
          { inherit value; }
        ];
      }).config.value;
in
builtins.deepSeq checked value
