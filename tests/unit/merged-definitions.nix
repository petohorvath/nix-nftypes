# A schema type used as an option merges the definitions of several
# modules, and a rule across a body's fields holds for the merged value:
# each definition alone may hold half of it. The module system checks a
# type on each definition alone, so two modules could build a delete
# Selector with both a name and a handle, or a reset before another
# command, and a base chain split across modules failed.
{ lib, nftlib, ... }:
let
  inherit (nftlib) types;

  # The option's value, forced in full, for the definitions `defs`.
  merge =
    type: defs:
    let
      value =
        (lib.evalModules {
          modules = [
            { options.o = lib.mkOption { inherit type; }; }
          ]
          ++ map (def: { o = def; }) defs;
        }).config.o;
    in
    builtins.deepSeq value value;

  scope = {
    family = "inet";
    table = "t";
  };
in
{
  testRulesetResetBeforeAnotherModulesCommandThrows = {
    expr = merge types.ruleset [
      {
        nftables = [
          {
            reset.counter = scope // {
              name = "c";
            };
          }
        ];
      }
      {
        nftables = [
          {
            add.table = {
              family = "inet";
              name = "t";
            };
          }
        ];
      }
    ];
    expectedError = {
      type = "ThrownError";
      msg = "A definition for option `o' is not of type `nft ruleset whose reset of a counter, quota, set, map, or rule is its last command'";
    };
  };

  testDeleteSelectorNameAndHandleFromTwoModulesThrows = {
    expr = merge types.objectBodies.deleteSetBody [
      (scope // { name = "s"; })
      { handle = 5; }
    ];
    expectedError = {
      type = "ThrownError";
      msg = "A definition for option `o' is not of type `set Selector with exactly one of name and handle'";
    };
  };

  testBaseChainFromTwoModulesValidates = {
    expr = merge types.objectBodies.chainBody [
      (
        scope
        // {
          name = "input";
          type = "filter";
          hook = "input";
          prio = 0;
        }
      )
      { policy = "drop"; }
    ];
    expected = {
      family = "inet";
      table = "t";
      name = "input";
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      comment = null;
      dev = null;
    };
  };

  testNatAddressFromAnotherModuleValidates = {
    expr =
      (merge (types.statementOf [ "snat" ]) [
        { snat.family = "ip"; }
        { snat.addr = "192.0.2.1"; }
      ]).snat.addr;
    expected = "192.0.2.1";
  };

  # A single definition still fails as before.
  testIncompleteBaseChainThrows = {
    expr = merge types.objectBodies.chainBody [
      (
        scope
        // {
          name = "input";
          type = "filter";
        }
      )
    ];
    expectedError = {
      type = "ThrownError";
      msg = "is not of type `chain body with type, hook and prio all set";
    };
  };
}
