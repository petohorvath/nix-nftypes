{ lib, nftlib }:

# DSL-level validation tests. Each case constructs a DSL value with a
# clearly-invalid field and asserts that evaluation throws — proving the
# DSL surface routes user input through the matching schema submodule
# instead of letting type errors leak into the rendered JSON (where
# `nft -j -f` silently drops broken sections).
#
# Companion suite: tests/dsl-validation-messages.nix runs representative
# cases through `nix-instantiate --eval` and asserts the stderr names the
# offending path (e.g. "chains.c.prio: …"). This file checks the failure;
# that one checks the message format.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toJson;

  # Force evaluation of the rendered JSON so the schema actually runs.
  # Without `toJson` the table tree is just a marked attrset and no
  # evalModules call is triggered.
  renders = rulesetValue: (builtins.tryEval (toJson (dsl.ruleset rulesetValue))).success;

  # Ownership is a property of table trees, shared by command and block
  # output. Use valid but conflicting values so schema type errors cannot
  # mask a missing scope check. The sibling exists in the rule-chain case:
  # redirecting a rule to another declared chain must still be rejected.
  scopeConflicts = {
    chainFamily.chains.input.family = "ip";
    chainTable.chains.input.table = "other";
    chainName.chains.input.name = "other";
    objectFamily.counters.hits.family = "ip";
    objectTable.counters.hits.table = "other";
    objectName.counters.hits.name = "other";
    ruleFamily.chains.input.rules = [
      {
        family = "ip";
        expr = [ dsl.accept ];
      }
    ];
    ruleTable.chains.input.rules = [
      {
        table = "other";
        expr = [ dsl.accept ];
      }
    ];
    ruleChain.chains = {
      input.rules = [
        {
          chain = "output";
          expr = [ dsl.accept ];
        }
      ];
      output = { };
    };
  };
  tableRenderers = {
    json = node: toJson (dsl.ruleset [ node ]);
    text = node: nftlib.toText (dsl.ruleset [ node ]);
    textPretty = node: nftlib.toTextPretty (dsl.ruleset [ node ]);
    block = nftlib.toTextBlock;
    blockPretty = nftlib.toTextBlockPretty;
  };
  scopeTests = lib.concatMapAttrs (
    name: body:
    lib.mapAttrs' (
      form: render:
      lib.nameValuePair "testTreeScope_${name}_${form}" {
        expr = (builtins.tryEval (render (dsl.table "inet" "fw" body))).success;
        expected = false;
      }
    ) tableRenderers
  ) scopeConflicts;

  tests = {
    testTableAndRulesetConstructionStayLazy = {
      expr =
        let
          node = dsl.table "inet" "fw" { chains.input.prio = "invalid"; };
        in
        {
          table = (builtins.tryEval node).success;
          ruleset = (builtins.tryEval (dsl.ruleset [ node ])).success;
          rendered = (builtins.tryEval (toJson (dsl.ruleset [ node ]))).success;
        };
      expected = {
        table = true;
        ruleset = true;
        rendered = false;
      };
    };

    testChainDeclarationDoesNotForceRuleBodies = {
      expr = toJson (
        builtins.elemAt
          (dsl.ruleset [
            (dsl.table "inet" "fw" { chains.input.rules = [ (throw "rule body forced") ]; })
          ]).nftables
          1
      );
      expected = toJson {
        add.chain = {
          family = "inet";
          table = "fw";
          name = "input";
        };
      };
    };

    testTreeMatchingExplicitScopeAccepted = {
      expr = lib.mapAttrs (
        _: render:
        (builtins.tryEval (
          render (
            dsl.table "inet" "fw" {
              chains.input = {
                family = "inet";
                table = "fw";
                name = "input";
                rules = [
                  {
                    family = "inet";
                    table = "fw";
                    chain = "input";
                    expr = [ dsl.accept ];
                  }
                ];
              };
              counters.hits = {
                family = "inet";
                table = "fw";
                name = "hits";
              };
            }
          )
        )).success
      ) tableRenderers;
      expected = lib.mapAttrs (_: _: true) tableRenderers;
    };

    # Table trees are a structural DSL surface rather than a schema body.
    # Reject misspelled collection names instead of silently dropping them
    # while expanding the tree.
    testTableUnknownCollectionRejected = {
      expr = renders [
        (dsl.table "inet" "t" {
          chians.c = { };
        })
      ];
      expected = false;
    };

    testTableTypeMarkerAccepted = {
      expr = renders [
        (dsl.table "inet" "t" {
          _type = "example.table";
        })
      ];
      expected = true;
    };

    # The user's bug. Schema `chainBody.prio` is `nullOr int`; passing a
    # symbolic priority like "filter" used to render to `"prio":"filter"`
    # and the kernel silently dropped the base-chain attrs.
    testChainsCPrioStringRejected = {
      expr = renders [
        (dsl.table "inet" "t" {
          chains.c = {
            type = "filter";
            hook = "input";
            policy = "drop";
            prio = "filter";
          };
        })
      ];
      expected = false;
    };

    # ----- command-builder constructors (commands.nix) --------------------

    testCreateChainPrioStringRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.create.chain {
              family = "ip";
              table = "t";
              name = "c";
              prio = "filter";
            }
          )
        )).success;
      expected = false;
    };

    testDeleteCounterBadFamilyRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.delete.counter {
              family = "wireguard";
              table = "t";
              name = "ctr";
            }
          )
        )).success;
      expected = false;
    };

    testListMapBadTypeRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.list.map {
              family = "ip";
              table = "t";
              name = "m";
              type = 123;
            }
          )
        )).success;
      expected = false;
    };

    testResetRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.reset.rule {
              family = "ip";
              table = "t";
              chain = "c";
              expr = [ ];
              handle = "not-a-number";
            }
          )
        )).success;
      expected = false;
    };

    testRenameChainBadNewnameRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.rename.chain {
              family = "ip";
              table = "t";
              name = "c";
              newname = 42;
            }
          )
        )).success;
      expected = false;
    };

    testReplaceRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.replace {
              family = "ip";
              table = "t";
              chain = "c";
              expr = [ ];
              handle = "abc";
            }
          )
        )).success;
      expected = false;
    };

    testInsertRuleBadIndexRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.insert {
              family = "ip";
              table = "t";
              chain = "c";
              expr = [ ];
              index = -1;
            }
          )
        )).success;
      expected = false;
    };

    # ----- flush helpers and standalone rule (ruleset.nix) ----------------

    testFlushTableBadFamilyRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushTable {
              family = "wireguard";
              name = "t";
            }
          )
        )).success;
      expected = false;
    };

    testFlushChainBadHandleRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushChain {
              family = "ip";
              table = "t";
              name = "c";
              handle = "not-a-number";
            }
          )
        )).success;
      expected = false;
    };

    testFlushSetMissingTypeRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushSet {
              family = "ip";
              table = "t";
              name = "s";
            }
          )
        )).success;
      expected = false;
    };

    testFlushMapMissingMapRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushMap {
              family = "ip";
              table = "t";
              name = "m";
              type = "ipv4_addr";
            }
          )
        )).success;
      expected = false;
    };

    testFlushMeterBadTableRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushMeter {
              family = "ip";
              table = 42;
              name = "m";
            }
          )
        )).success;
      expected = false;
    };

    testFlushRulesetBadFamilyRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.flushRuleset {
              family = "wireguard";
            }
          )
        )).success;
      expected = false;
    };

    testStandaloneRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.rule {
              family = "ip";
              table = "t";
              chain = "c";
              expr = [ ];
              handle = "abc";
            }
          )
        )).success;
      expected = false;
    };

    # ----- table-tree leaves (lib/table.nix) ------------------------------
    # One per plural-keyed object container, each picking a clearly-bad
    # value for the matching schema submodule. Asserts the leaf-validation
    # in lib/table.nix routes every kind through the right body type.

    testTreeTableBadFlagsRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          flags = [ "no-such-flag" ];
        })
      ];
      expected = false;
    };

    testTreeRuleBadHandleRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          chains.c = {
            rules = [
              {
                expr = [ ];
                handle = "abc";
              }
            ];
          };
        })
      ];
      expected = false;
    };

    testTreeSetBadTypeRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          sets.s = {
            type = 42;
          };
        })
      ];
      expected = false;
    };

    testTreeMapMissingMapRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          maps.m = {
            type = "ipv4_addr";
          };
        })
      ];
      expected = false;
    };

    # `setElem` (the type behind `elem`) accepts string/int/bool/list as
    # bare expressions, so we exercise the schema via a different field —
    # `family` is a strict enum, easy to violate cleanly.
    testTreeElementBadFamilyRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          elements.s = {
            family = "wireguard";
            elements = [ "1.2.3.4" ];
          };
        })
      ];
      expected = false;
    };

    # flowtableBody.hook accepts `nullOr hook`, and flowtable.dev is
    # required to be a string list — pass a number to force a clean failure.
    testTreeFlowtableBadDevRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          flowtables.ft = {
            hook = "ingress";
            prio = 0;
            dev = 42;
          };
        })
      ];
      expected = false;
    };

    testTreeCounterBadPacketsRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          counters.c = {
            packets = "lots";
          };
        })
      ];
      expected = false;
    };

    testTreeQuotaBadBytesRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          quotas.q = {
            bytes = "infinity";
          };
        })
      ];
      expected = false;
    };

    testTreeLimitMissingPerRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          limits.l = {
            rate = 100;
          };
        })
      ];
      expected = false;
    };

    testTreeCtHelperBadProtocolRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          ctHelpers.h = {
            protocol = "icmp";
          };
        })
      ];
      expected = false;
    };

    testTreeCtTimeoutBadL3protoRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          ctTimeouts.t = {
            l3proto = "ipx";
          };
        })
      ];
      expected = false;
    };

    testTreeCtExpectationBadDportRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          ctExpectations.e = {
            dport = 99999;
          };
        })
      ];
      expected = false;
    };

    testTreeSecmarkBadContextRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          secmarks.s = {
            context = 42;
          };
        })
      ];
      expected = false;
    };

    testTreeSynproxyMissingMssRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          synproxies.sp = {
            wscale = 7;
          };
        })
      ];
      expected = false;
    };

    testTreeTunnelBadTypeRejected = {
      expr = renders [
        (dsl.table "ip" "t" {
          tunnels.tn = {
            type = "wireguard";
          };
        })
      ];
      expected = false;
    };

    # ----- happy path: a complete, valid ruleset still renders -----------

    testTreeAcceptedRulesetSucceeds = {
      expr =
        (builtins.tryEval (
          toJson (
            dsl.ruleset [
              (dsl.table "ip" "t" {
                chains.c = {
                  type = "filter";
                  hook = "input";
                  prio = 0;
                  policy = "accept";
                  rules = [ [ dsl.accept ] ];
                };
              })
            ]
          )
        )).success;
      expected = true;
    };
  }
  // scopeTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "dsl-validation-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
