{
  fixtures,
  lib,
  nftlib,
  ...
}:

# Parity tests for the block-form text renderer (toTextBlock /
# toTextBlockPretty).
#
# Each case asserts the exact emitted string for a `dsl.table` value.
# Mirrors tests/suites/text-parity.nix's pattern but exercises the block-form
# path: no `add` keyword, no `<family> <table>` prefix on object
# headers, rules folded as inline statements inside their parent
# chain's brace block.
#
# The companion live-parser suite (tests/suites/text-block-integration.nix)
# feeds block output for the shared fixture tables to the upstream
# nftables parser.

let
  inherit (fixtures.blockTables) baseChain limitTable referencedTable;
  inherit (nftlib)
    dsl
    toTextBlock
    toTextBlockPretty
    ;

in
{
  # ---- empty input ---------------------------------------------------
  testEmptyTableCompact = {
    expr = toTextBlock (dsl.table "inet" "fw" { });
    expected = "";
  };

  testEmptyTablePretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { });
    expected = "";
  };

  # An empty top-level elements collection emits no standalone command and is
  # therefore a valid no-op for both public block renderers.
  testEmptyElementsCollectionCompact = {
    expr = toTextBlock (dsl.table "inet" "fw" { elements = { }; });
    expected = "";
  };

  testEmptyElementsCollectionPretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { elements = { }; });
    expected = "";
  };

  # Block renderers accept only declarative table nodes. Raw commands must
  # not be silently discarded or rendered without their table context.
  testRawTableCommandRejected = {
    expr = toTextBlock {
      add.table = {
        family = "inet";
        name = "fw";
      };
    };
    expectedError.msg = "block-form text rendering expects one dsl\\.table node";
  };

  testRawChainCommandRejectedPretty = {
    expr = toTextBlockPretty {
      add.chain = {
        family = "inet";
        table = "fw";
        name = "input";
      };
    };
    expectedError.msg = "block-form text rendering expects one dsl\\.table node";
  };

  # Assertions cross the public table interface. The old internal command
  # envelope and its partition/regroup protocol no longer exist.
  testRulesetEnvelopeRejected = {
    expr = toTextBlock (dsl.ruleset [ (dsl.table "inet" "fw" { }) ]);
    expectedError.msg = "block-form text rendering expects one dsl\\.table node";
  };

  testTableListRejectedPretty = {
    expr = toTextBlockPretty [
      (dsl.table "inet" "fw" { })
      (dsl.table "inet" "other" { })
    ];
    expectedError.msg = "block-form text rendering expects one dsl\\.table node";
  };

  testUnknownTableKeyRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { chians.input = { }; });
    expectedError.msg = "dsl\\.table inet\\.fw has unsupported key.*chians";
  };

  # Omitting wrapper fields from output must not skip their validation,
  # including when there are no declarations to render.
  testInvalidEmptyTableFamilyRejected = {
    expr = toTextBlock (dsl.table "invalid" "fw" { });
    expectedError.msg = "option .family. is not of type";
  };

  testInvalidEmptyTableFlagsRejectedPretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { flags = [ "invalid" ]; });
    expectedError.msg = "flags\\..*is not of type";
  };

  testInvalidEmptyTableCommentRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { comment = 7; });
    expectedError.msg = "option .*comment.*not of type";
  };

  testTableOptionsBelongToOmittedWrapper = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        comment = "table";
        flags = [ "dormant" ];
        handle = 7;
      }
    );
    expected = "";
  };

  testInvalidChainPriorityRejected = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          prio = "filter";
        };
      }
    );
    expectedError.msg = "chains\\.input\\.prio";
  };

  testInvalidRuleHandleRejectedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          {
            expr = [ dsl.accept ];
            handle = "invalid";
          }
        ];
      }
    );
    expectedError.msg = "chains\\.input\\.rules\\.\"?0\"?\\.handle";
  };

  testInvalidNamedObjectRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { counters.hits.packets = "lots"; });
    expectedError.msg = "counters\\.hits\\.packets.*is not of type";
  };

  testUnsafeIfnameElementRejectedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        sets.interfaces = {
          type = "ifname";
          elements = [ "eth0,eth1" ];
        };
      }
    );
    expectedError.msg = "sets\\.interfaces: .*is not a safe interface name";
  };

  # Standalone `element` is an imperative command and has no legal form
  # inside a `table ... {}` block. Block renderers must reject this DSL tree
  # instead of emitting parser-invalid `element name { ... }` text.
  testStandaloneElementsRejectedCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        sets.blocked = {
          type = "ipv4_addr";
        };
        elements.blocked = {
          elements = [ "192.0.2.1" ];
        };
      }
    );
    expectedError.msg = "block-form text rendering cannot embed standalone table elements";
  };

  testStandaloneElementsRejectedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        maps.services = {
          type = "inet_service";
          map = "inet_service";
        };
        elements.services = {
          elements = [
            [
              80
              8080
            ]
          ];
        };
      }
    );
    expectedError.msg = "block-form text rendering cannot embed standalone table elements";
  };

  # ---- chain only (base chain, no rules) -----------------------------
  testBaseChainNoRulesCompact = {
    expr = toTextBlock (dsl.table "inet" "fw" { chains.input = baseChain; });
    expected = "chain input { type filter hook input priority 0; }";
  };

  testBaseChainNoRulesPretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { chains.input = baseChain; });
    expected = ''
      chain input {
        type filter hook input priority 0;
      }'';
  };

  # ---- chain with rules (rules become inline statements) -------------
  testChainWithRulesCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          policy = "drop";
          rules = [
            [ dsl.accept ]
            [ dsl.drop ]
          ];
        };
      }
    );
    expected = "chain input { type filter hook input priority 0; policy drop; accept; drop; }";
  };

  testChainWithRulesPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          policy = "drop";
          rules = [
            [ dsl.accept ]
            [ dsl.drop ]
          ];
        };
      }
    );
    expected = ''
      chain input {
        type filter hook input priority 0;
        policy drop;
        accept;
        drop;
      }'';
  };

  # ---- rule with comment ---------------------------------------------
  testChainRuleWithCommentPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [
            {
              expr = [ dsl.accept ];
              comment = "allow";
            }
          ];
        };
      }
    );
    expected = ''
      chain input {
        type filter hook input priority 0;
        accept comment "allow";
      }'';
  };

  testMatchingScopeAndCleanedRule = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        _type = "example.table";
        chains.input = {
          family = "inet";
          table = "fw";
          name = "input";
          comment = null;
          rules = [
            {
              family = "inet";
              table = "fw";
              chain = "input";
              expr = [
                (dsl.counter { packets = 1; })
                dsl.accept
              ];
              comment = "allow";
              handle = 7;
            }
          ];
        };
      }
    );
    expected = "chain input { counter packets 1 accept comment \"allow\"; }";
  };

  # ---- set / map / counter (block-form decls, no add prefix) ---------
  testSetBlockCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
      }
    );
    expected = "set lan_v4 { type ipv4_addr; flags interval; }";
  };

  testSetBlockPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
      }
    );
    expected = ''
      set lan_v4 {
        type ipv4_addr;
        flags interval;
      }'';
  };

  testCounterBlockCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        counters.hits = { };
      }
    );
    expected = "counter hits { }";
  };

  # Regression: pre-fix emitted `accept; accept }`, which `nft -f`
  # rejects with `unexpected '}'`.
  testChainTwoRulesEndsWithSemiCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.fwd = (baseChain // { hook = "forward"; }) // {
          rules = [
            [ dsl.accept ]
            [ dsl.accept ]
          ];
        };
      }
    );
    expected = "chain fwd { type filter hook forward priority 0; accept; accept; }";
  };

  # Same regression for sibling decls inside the table block.
  testMultipleChildrenAllEndWithSemiCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [ [ dsl.accept ] ];
        };
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
      }
    );
    expected = "chain input { type filter hook input priority 0; accept; }\nset lan_v4 { type ipv4_addr; flags interval; }";
  };

  # ---- mixed children at the same indent level -----------------------
  testMixedChainAndSetPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [ [ dsl.accept ] ];
        };
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
      }
    );
    expected = ''
      chain input {
        type filter hook input priority 0;
        accept;
      }
      set lan_v4 {
        type ipv4_addr;
        flags interval;
      }'';
  };

  # ---- multiple chains, rules grouped by chain -----------------------
  testTwoChainsWithRulesPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [ [ dsl.accept ] ];
        };
        chains.output = (baseChain // { hook = "output"; }) // {
          rules = [ [ dsl.drop ] ];
        };
      }
    );
    expected = ''
      chain input {
        type filter hook input priority 0;
        accept;
      }
      chain output {
        type filter hook output priority 0;
        drop;
      }'';
  };

  testReferencesAndOrderingCompact = {
    expr = toTextBlock referencedTable;
    expected = lib.concatStringsSep "\n" [
      "chain input { type filter hook input priority 0; tcp dport vmap @dispatch; }"
      "chain service { ip saddr @trusted counter name \"hits\" accept; drop; }"
      "counter hits { }"
      "map dispatch { type inet_service : verdict; elements = { 22 : jump service }; }"
      "set trusted { type ipv4_addr; elements = { 192.0.2.1 }; }"
    ];
  };

  testReferencesAndOrderingPretty = {
    expr = toTextBlockPretty referencedTable;
    expected = ''
      chain input {
        type filter hook input priority 0;
        tcp dport vmap @dispatch;
      }
      chain service {
        ip saddr @trusted counter name "hits" accept;
        drop;
      }
      counter hits { }
      map dispatch {
        type inet_service : verdict;
        elements = { 22 : jump service };
      }
      set trusted {
        type ipv4_addr;
        elements = { 192.0.2.1 };
      }'';
  };

  testLimitsCompact = {
    expr = toTextBlock limitTable;
    expected = lib.concatStringsSep "\n" [
      "chain input { limit rate over 10 kbytes/minute burst 5 bytes; limit name \"slow\" accept; }"
      "limit slow { rate 5/second burst 10 packets; comment \"packet budget\"; }"
    ];
  };

  testLimitsPretty = {
    expr = toTextBlockPretty limitTable;
    expected = ''
      chain input {
        limit rate over 10 kbytes/minute burst 5 bytes;
        limit name "slow" accept;
      }
      limit slow {
        rate 5/second burst 10 packets;
        comment "packet budget";
      }'';
  };
}
