# `validate`, the explicit Validation step: a value that fits its schema
# type comes back ready to render, and one that does not throws naming
# the field, however deep the lazy submodule check sits.
{ nftlib, ... }:
let
  inherit (nftlib)
    toJson
    toText
    types
    validate
    ;

  ruleset = {
    nftables = [
      { flush.ruleset = null; }
      {
        add.table = {
          family = "inet";
          name = "filter";
        };
      }
    ];
  };

  # The bad field sits two submodules deep, where an unforced check would
  # never run.
  badPolicy = {
    nftables = [
      {
        add.chain = {
          family = "inet";
          table = "filter";
          name = "input";
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "allow";
        };
      }
    ];
  };
in
{
  testValidRulesetRendersAsWritten = {
    expr = toJson (validate types.ruleset ruleset);
    expected = "{\"nftables\":[{\"flush\":{\"ruleset\":null}},{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}]}";
  };

  # Unset options come back absent, not as their `null` defaults.
  testValidValueComesBackUnchanged = {
    expr = validate types.ruleset ruleset;
    expected = ruleset;
  };

  # A selected rule may omit `expr`, which `validate` no longer fills in;
  # the text renderers still render it.
  testValidRuleSelectionWithoutExprRendersAsText = {
    expr = toText (
      validate types.ruleset {
        nftables = [
          {
            delete.rule = {
              family = "ip";
              table = "t";
              chain = "c";
              handle = 4;
            };
          }
        ];
      }
    );
    expected = "delete rule ip t c handle 4";
  };

  testValidPrimitivePassesThrough = {
    expr = validate types.family "inet";
    expected = "inet";
  };

  testNestedFieldErrorNamesTheField = {
    expr = validate types.ruleset badPolicy;
    expectedError = {
      type = "ThrownError";
      msg = "validate\\.nftables.*policy";
    };
  };

  testPrimitiveErrorNamesValidate = {
    expr = validate types.family "inet6";
    expectedError = {
      type = "ThrownError";
      msg = "`validate' is not of type";
    };
  };
}
