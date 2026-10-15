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

  The evaluated value, with option defaults filled in. Cleaning removes
  the unset ones again when the value is rendered.

  Submodule checks are lazy, so the result is forced in full before it is
  returned: every check runs, however deep. A mismatch throws the module
  system's error, whose option path starts with `validate`.
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
builtins.deepSeq checked checked
