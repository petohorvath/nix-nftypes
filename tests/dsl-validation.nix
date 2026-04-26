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
  inherit (nftlib) toJSON;

  # Force evaluation of the rendered JSON so the schema actually runs.
  # Without `toJSON` the table tree is just a marked attrset and no
  # evalModules call is triggered.
  renders = rulesetValue: (builtins.tryEval (toJSON (dsl.ruleset rulesetValue))).success;

  tests = {
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
        (builtins.tryEval (toJSON (dsl.create.chain {
          family = "ip";
          table = "t";
          name = "c";
          prio = "filter";
        }))).success;
      expected = false;
    };

    testDeleteCounterBadFamilyRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.delete.counter {
          family = "wireguard";
          table = "t";
          name = "ctr";
        }))).success;
      expected = false;
    };

    testListMapBadTypeRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.list.map {
          family = "ip";
          table = "t";
          name = "m";
          type = 123;
        }))).success;
      expected = false;
    };

    testResetRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.reset.rule {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          handle = "not-a-number";
        }))).success;
      expected = false;
    };

    testRenameChainBadNewnameRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.rename.chain {
          family = "ip";
          table = "t";
          name = "c";
          newname = 42;
        }))).success;
      expected = false;
    };

    testReplaceRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.replace {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          handle = "abc";
        }))).success;
      expected = false;
    };

    testInsertRuleBadIndexRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.insert {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          index = -1;
        }))).success;
      expected = false;
    };

    # ----- flush helpers and standalone rule (ruleset.nix) ----------------

    testFlushTableBadFamilyRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushTable {
          family = "wireguard";
          name = "t";
        }))).success;
      expected = false;
    };

    testFlushChainBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushChain {
          family = "ip";
          table = "t";
          name = "c";
          handle = "not-a-number";
        }))).success;
      expected = false;
    };

    testFlushSetMissingTypeRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushSet {
          family = "ip";
          table = "t";
          name = "s";
        }))).success;
      expected = false;
    };

    testFlushMapMissingMapRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushMap {
          family = "ip";
          table = "t";
          name = "m";
          type = "ipv4_addr";
        }))).success;
      expected = false;
    };

    testFlushMeterBadTableRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushMeter {
          family = "ip";
          table = 42;
          name = "m";
        }))).success;
      expected = false;
    };

    testFlushRulesetBadFamilyRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.flushRuleset {
          family = "wireguard";
        }))).success;
      expected = false;
    };

    testStandaloneRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.rule {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          handle = "abc";
        }))).success;
      expected = false;
    };

    # ----- table-tree leaves (render.nix path) ----------------------------
    # One per plural-keyed object container, each picking a clearly-bad
    # value for the matching schema submodule. Asserts the leaf-validation
    # in render.nix routes every kind through the right body type.

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

    # flowtableBody.hook accepts `nullOr hookType`, and flowtable.dev is
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
        (builtins.tryEval (toJSON (dsl.ruleset [
          (dsl.table "ip" "t" {
            chains.c = {
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "accept";
              rules = [ [ dsl.accept ] ];
            };
          })
        ]))).success;
      expected = true;
    };
  };

  runTests =
    pkgs:
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs.runCommandLocal "dsl-validation-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} validation tests passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "dsl-validation-tests-fail" { } ''
        cat <<'EOF'
        DSL validation tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests;
}
