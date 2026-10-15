/*
  Reach check: every statement tag, expression tag, and command/object
  pair the schema accepts must appear in an Integration case whose JSON
  loads, so that it reaches a real nft parser. A gap is allowed only as a
  pending entry naming the open ticket under #24 that adds its case, or as
  a Named exclusion naming its Known difference (../fixtures/reach.nix).
*/
{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:
let
  inherit (helpers) reach;

  tagsOf = union: builtins.attrNames union.functor.payload.tags;

  # What the schema accepts.
  inventory = {
    statements = tagsOf nftlib.types.statement;
    expressions = tagsOf nftlib.types.taggedExpression;
    commands = lib.concatLists (
      lib.mapAttrsToList (
        verb: option: map (kind: "${verb} ${kind}") (tagsOf option.type)
      ) nftlib.types.command.functor.payload.tags
    );
  };

  reachedBy = reach.reachedBy inventory.expressions;

  # What the Integration cases reach, in the JSON that nft loads.
  reached =
    let
      byCase = map (
        case: reachedBy (builtins.fromJSON (nftlib.toJson case.ruleset))
      ) fixtures.integrationCases.cases;
    in
    lib.genAttrs [ "statements" "expressions" "commands" ] (
      category: lib.unique (lib.concatMap (case: case.${category}) byCase)
    );

  # The reach check for one category.
  reachTest = category: label: {
    expr = reach.problems {
      inherit category;
      inventory = inventory.${label};
      reached = reached.${label};
      pending = fixtures.reach.pending.${label};
      knownDifferences = fixtures.reach.knownDifferences.${label};
    };
    expected = [ ];
  };

  tcpDport.payload = {
    protocol = "tcp";
    field = "dport";
  };

  # The verdict for a two-tag statement inventory, with `overrides`.
  problemsOf =
    overrides:
    reach.problems (
      {
        category = "statement";
        inventory = [
          "counter"
          "log"
        ];
        pending = { };
        knownDifferences = { };
      }
      // overrides
    );

  # A rule in the shape `nftlib.toJson` writes, holding `statements`.
  ruleWith = statements: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "t";
          chain = "c";
          expr = statements;
        };
      }
    ];
  };
in
{
  testEveryStatementReachesNft = reachTest "statement" "statements";
  testEveryExpressionReachesNft = reachTest "expression" "expressions";
  testEveryCommandPairReachesNft = reachTest "command" "commands";

  # The inventory comes from the schema's unions, so a change in how
  # nixpkgs stores `types.attrTag` choices can't empty it unnoticed.
  testInventoryHasTheSchemaTags = {
    expr = {
      statement = builtins.elem "match" inventory.statements;
      expression = builtins.elem "payload" inventory.expressions;
      command = builtins.elem "add rule" inventory.commands;
    };
    expected = {
      statement = true;
      expression = true;
      command = true;
    };
  };

  testReachedStatementsOfARule = {
    expr =
      (reachedBy (ruleWith [
        { counter = null; }
        { accept = null; }
      ])).statements;
    expected = [
      "accept"
      "counter"
    ];
  };

  testReachedNestedStatements = {
    expr =
      (reachedBy (ruleWith [
        {
          meter = {
            name = "m";
            key = tcpDport;
            stmt = {
              limit = {
                rate = 1;
                per = "second";
              };
            };
          };
        }
        {
          set = {
            op = "add";
            elem = tcpDport;
            set = "@s";
            stmt = [ { counter = null; } ];
          };
        }
      ])).statements;
    expected = [
      "counter"
      "limit"
      "meter"
      "set"
    ];
  };

  testReachedExpressionsOfAMatch = {
    expr =
      (reachedBy (ruleWith [
        {
          match = {
            op = "==";
            left = tcpDport;
            right.set = [
              22
              {
                range = [
                  1024
                  2048
                ];
              }
            ];
          };
        }
      ])).expressions;
    expected = [
      "payload"
      "range"
      "set"
    ];
  };

  # The verdicts in a verdict map are expressions, not statements.
  testReachedVerdictExpressions = {
    expr = removeAttrs (reachedBy (ruleWith [
      {
        vmap = {
          key = tcpDport;
          data.set = [
            [
              22
              { accept = null; }
            ]
            [
              80
              { jump.target = "web"; }
            ]
          ];
        };
      }
    ])) [ "commands" ];
    expected = {
      statements = [ "vmap" ];
      expressions = [
        "accept"
        "jump"
        "payload"
        "set"
      ];
    };
  };

  testReachedStatefulReferenceByMap = {
    expr =
      (reachedBy (ruleWith [
        {
          counter.map = {
            key = tcpDport;
            data.set = [
              [
                22
                "ssh"
              ]
            ];
          };
        }
      ])).expressions;
    expected = [
      "map"
      "payload"
      "set"
    ];
  };

  testLogPrefixIsNotAnExpression = {
    expr = (reachedBy (ruleWith [ { log.prefix = "dropped"; } ])).expressions;
    expected = [ ];
  };

  testReachedObjectExpressions = {
    expr =
      (reachedBy {
        nftables = [
          {
            add.set = {
              family = "inet";
              table = "t";
              name = "s";
              type.typeof = tcpDport;
            };
          }
          {
            add.element = {
              family = "inet";
              table = "t";
              name = "s";
              elem = [
                {
                  elem = {
                    val.prefix = {
                      addr = "10.0.0.0";
                      len = 8;
                    };
                    timeout = 60;
                  };
                }
              ];
            };
          }
        ];
      }).expressions;
    expected = [
      "elem"
      "payload"
      "prefix"
    ];
  };

  testReachedCommands = {
    expr =
      (reachedBy {
        nftables = [
          { flush.ruleset = null; }
          {
            add.table = {
              family = "inet";
              name = "t";
            };
          }
          {
            replace.rule = {
              family = "inet";
              table = "t";
              chain = "c";
              handle = 2;
              expr = [ { accept = null; } ];
            };
          }
          {
            delete."ct helper" = {
              family = "inet";
              table = "t";
              name = "h";
            };
          }
        ];
      }).commands;
    expected = [
      "add table"
      "delete ct helper"
      "flush ruleset"
      "replace rule"
    ];
  };

  testUncoveredTagFails = {
    expr = problemsOf { reached = [ "counter" ]; };
    expected = [
      "statement \"log\" is in no Integration case, so it never reaches nft: add a case that uses it to tests/fixtures/integration-cases.nix"
    ];
  };

  testCoveredPendingEntryFails = {
    expr = problemsOf {
      reached = [
        "counter"
        "log"
      ];
      pending.log = 50;
    };
    expected = [
      "statement \"log\" is in an Integration case now: delete its pending entry (#50) from tests/fixtures/reach.nix"
    ];
  };

  testCoveredExclusionFails = {
    expr = problemsOf {
      reached = [
        "counter"
        "log"
      ];
      knownDifferences.log = "nft ignores it";
    };
    expected = [
      "statement \"log\" is in an Integration case now: delete its Named exclusion from tests/fixtures/reach.nix"
    ];
  };

  testEntryOutsideInventoryFails = {
    expr = problemsOf {
      reached = [
        "counter"
        "log"
      ];
      pending.tunnel = 50;
      knownDifferences.xt = "Read-back only";
    };
    expected = [
      "statement \"tunnel\" has a pending entry, but the schema doesn't accept it: delete the entry from tests/fixtures/reach.nix"
      "statement \"xt\" has a Named exclusion, but the schema doesn't accept it: delete the entry from tests/fixtures/reach.nix"
    ];
  };

  testPendingEntryNamesATicket = {
    expr = problemsOf {
      reached = [ "counter" ];
      pending.log = 24;
    };
    expected = [
      "statement \"log\" has a pending entry naming #24, not an open ticket under #24"
    ];
  };

  testExclusionNamesItsKnownDifference = {
    expr = problemsOf {
      reached = [ "counter" ];
      knownDifferences.log = "";
    };
    expected = [
      "statement \"log\" has a Named exclusion with no Known difference: give the reason nft can't load it"
    ];
  };

  testPendingOrExcludedTagPasses = {
    expr = map problemsOf [
      {
        reached = [ "counter" ];
        pending.log = 50;
      }
      {
        reached = [ "counter" ];
        knownDifferences.log = "nft ignores it";
      }
    ];
    expected = [
      [ ]
      [ ]
    ];
  };

  testEntryBothPendingAndExcludedFails = {
    expr = problemsOf {
      reached = [ "counter" ];
      pending.log = 50;
      knownDifferences.log = "nft ignores it";
    };
    expected = [
      "statement \"log\" is both pending and a Named exclusion: keep one in tests/fixtures/reach.nix"
    ];
  };
}
