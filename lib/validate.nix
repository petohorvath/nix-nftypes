{ lib }:

/**
  Validate a value against a schema type, so a hand-written value can be
  checked before it is rendered; the renderers do not validate.

  # Inputs

  `type`
  : The schema type to check against, such as `types.ruleset`.

  `value`
  : The value to check.

  # Returns

  `value` unchanged. An option it leaves unset stays absent rather than
  taking its `null` default, or the empty list for a rule's `expr`, which
  the renderers fill. No schema type transforms its value, so the check
  adds nothing else.

  Submodule checks are lazy, so the checked value is forced in full before
  `value` is returned: every check runs, however deep. A mismatch throws
  the module system's error, whose option path starts with `validate`.
  Swapped arguments, a first argument that is no schema type, and a Table
  tree as `value` throw a `nix-nftypes: validate:` error instead.
*/
type: value:
let
  fail = import ./fail.nix { } "validate";
  inherit (import ./describe.nix { inherit lib; }) describe;
  inherit (import ./table-tree-marker.nix { }) isTableTree;

  checked =
    (lib.evalModules {
      modules = [
        {
          options.validate = lib.mkOption {
            inherit type;
            description = "The value under validation.";
          };
        }
        { validate = value; }
      ];
    }).config.validate;
in
if !(lib.isOptionType type) && lib.isOptionType value then
  fail "the arguments are swapped; call it as `validate type value`, such as `validate types.ruleset ruleset`"
else if !(lib.isOptionType type) then
  fail "expected a schema type, such as `types.ruleset`, as the first argument, got ${describe type}; call it as `validate type value`"
else if isTableTree value then
  fail "got a Table tree, which no schema type takes; expand it into a ruleset with `dsl.ruleset [ … ]`, which validates its bodies"
else
  builtins.deepSeq checked value
