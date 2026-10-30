# A module property, such as `lib.mkIf` or `lib.mkMerge`, is never data:
# only an option definition resolves one. Passed as a value, the module
# system checked the resolved value while the caller got the property
# back, so it rendered as `{"condition": …}` or `{"contents": …}`. Every
# public entry point throws on one, naming where it sits.
{ lib, nftlib, ... }:
let
  inherit (nftlib)
    dsl
    toJson
    toText
    toTextBlock
    types
    validate
    ;

  table = {
    family = "inet";
    name = "t";
  };

  hint = "which only the module system resolves; build the value with lib\\.optional, lib\\.optionalAttrs, or `//`$";
in
{
  testValidateTopLevelMkIfThrows = {
    expr = validate types.statement (lib.mkIf true { accept = null; });
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: got lib\\.mkIf, ${hint}";
    };
  };

  testValidateNestedMkMergeThrows = {
    expr = validate types.ruleset {
      nftables = [
        {
          add.table = lib.mkMerge [
            { family = "inet"; }
            { name = "t"; }
          ];
        }
      ];
    };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: nftables\\.0\\.add\\.table: got lib\\.mkMerge, ${hint}";
    };
  };

  testValidateMkDefaultThrows = {
    expr = validate types.ruleset {
      nftables = [
        {
          add.table = table // {
            name = lib.mkDefault "u";
          };
        }
      ];
    };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: nftables\\.0\\.add\\.table\\.name: got lib\\.mkOverride, as lib\\.mkDefault and lib\\.mkForce make, ${hint}";
    };
  };

  testValidateMkBeforeThrows = {
    expr = validate types.ruleset { nftables = lib.mkBefore [ ]; };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: validate: nftables: got lib\\.mkOrder, as lib\\.mkBefore and lib\\.mkAfter make, ${hint}";
    };
  };

  # A library's own `_type` marker is not a module property.
  testValidateOtherMarkersPass = {
    expr = validate types.family "inet";
    expected = "inet";
  };

  testStatementBuilderBodyThrows = {
    expr = dsl.log (lib.mkIf true { prefix = "x "; });
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.log: got lib\\.mkIf, ${hint}";
    };
  };

  testStatementBuilderFieldThrows = {
    expr = dsl.log { prefix = lib.mkIf true "x "; };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.log: prefix: got lib\\.mkIf, ${hint}";
    };
  };

  testCommandBuilderBodyThrows = {
    expr = dsl.add.set (
      lib.mkMerge [
        (table // { name = "s"; })
        { type = "ipv4_addr"; }
      ]
    );
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.add\\.set: got lib\\.mkMerge, ${hint}";
    };
  };

  testTableTreeThrows = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = lib.mkMerge [ { type = "ipv4_addr"; } ];
        })
      ]
    );
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.table inet\\.t: sets\\.s: got lib\\.mkMerge, ${hint}";
    };
  };

  testTableTreeRuleThrows = {
    expr = toTextBlock (
      dsl.table "inet" "t" {
        chains.c.rules = [ [ (lib.mkIf false dsl.accept) ] ];
      }
    );
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.table inet\\.t: chains\\.c\\.rules\\.0\\.expr\\.0: got lib\\.mkIf, ${hint}";
    };
  };

  testRulesetChildThrows = {
    expr = dsl.ruleset [ (lib.mkIf false { add.table = table; }) ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 0: got lib\\.mkIf, ${hint}";
    };
  };

  testRulesetRawCommandFieldThrows = {
    expr = dsl.ruleset [
      {
        add.table = table // {
          name = lib.mkForce "u";
        };
      }
    ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 0\\.add\\.table\\.name: got lib\\.mkOverride, as lib\\.mkDefault and lib\\.mkForce make, ${hint}";
    };
  };

  testToJsonThrows = {
    expr = toJson { nftables = [ (lib.mkIf true { add.table = table; }) ]; };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: toJson: nftables\\.0: got lib\\.mkIf, ${hint}";
    };
  };

  testToTextThrows = {
    expr = toText { nftables = [ { add.table = lib.mkMerge [ table ]; } ]; };
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: toText: nftables\\.0\\.add\\.table: got lib\\.mkMerge, ${hint}";
    };
  };
}
