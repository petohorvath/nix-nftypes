# `validate`, the explicit Validation step: a value that fits its schema
# type comes back ready to render, and one that does not throws naming
# the field, however deep the lazy submodule check sits.
{ nftlib, ... }:
let
  inherit (nftlib) toJson types validate;

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
