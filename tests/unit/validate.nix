# `validate`, the explicit Validation step: a value that fits its schema
# type comes back ready to render, and one that does not throws naming
# the field, however deep the lazy submodule check sits.
{ nftlib, ... }:
let
  inherit (nftlib)
    dsl
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

  # `validate` leaves a rule's unset `expr` out, and the renderers fill the
  # empty list nft's JSON parser requires on a destroyed rule.
  testValidRuleSelectionWithoutExprRenders =
    let
      selection = {
        nftables = [
          {
            destroy.rule = {
              family = "ip";
              table = "t";
              chain = "c";
              handle = 4;
            };
          }
        ];
      };
      validated = validate types.ruleset selection;
    in
    {
      expr = {
        inherit validated;
        json = toJson validated;
        text = toText validated;
      };
      expected = {
        validated = selection;
        json = "{\"nftables\":[{\"destroy\":{\"rule\":{\"chain\":\"c\",\"expr\":[],\"family\":\"ip\",\"handle\":4,\"table\":\"t\"}}}]}";
        text = "destroy rule ip t c handle 4\n";
      };
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

  # `validate value type` is the likeliest slip, and the module system
  # would report it from deep inside its own internals.
  testSwappedArgumentsThrowNamingValidate = {
    expr = validate ruleset types.ruleset;
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: the arguments are swapped; call it as `validate type value`, such as `validate types\\.ruleset ruleset`$";
    };
  };

  testNonTypeFirstArgumentThrowsNamingValidate = {
    expr = validate "ruleset" ruleset;
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: expected a schema type, such as `types\\.ruleset`, as the first argument, got a string; call it as `validate type value`$";
    };
  };

  # No schema type takes a Table tree; `dsl.ruleset` expands one into the
  # commands `types.ruleset` takes.
  testTableTreeValueThrowsNamingValidate = {
    expr = validate types.ruleset (dsl.table "inet" "filter" { });
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: got a Table tree, which no schema type takes; expand it into a ruleset with `dsl\\.ruleset \\[ … \\]`, which validates its bodies$";
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
