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
  taking its `null` default, or the empty list for a rule's `expr`. No
  schema type transforms its value, so the check adds nothing else.

  Submodule checks are lazy, so the checked value is forced in full before
  `value` is returned: every check runs, however deep. A mismatch throws
  the module system's error, whose option path starts with `validate`.
*/
type: value:
let
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
builtins.deepSeq checked value
