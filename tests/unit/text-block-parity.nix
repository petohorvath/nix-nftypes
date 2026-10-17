{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:

# Parity tests for the block-form text renderer (toTextBlock /
# toTextBlockPretty).
#
# Each case asserts the exact emitted string for a `dsl.table` value.
# Mirrors tests/unit/text-parity.nix's pattern but exercises the block-form
# path: no `add` keyword, no `<family> <table>` prefix on object
# headers, rules folded as inline statements inside their parent
# chain's brace block.
#
# The companion live-parser suite (tests/integration/text-block.nix)
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
  # nft's JSON parser ignores a set or map comment, so block form refuses
  # it as imperative text does.
  testSetCommentRefused = {
    expr = toTextBlock (
      dsl.table "inet" "t" {
        sets.s = {
          type = "ipv4_addr";
          comment = "blocked hosts";
        };
      }
    );
    expectedError.msg = helpers.refusals.jsonIgnored "set comment";
  };

  testMapCommentRefused = {
    expr = toTextBlockPretty (
      dsl.table "inet" "t" {
        maps.m = {
          type = "ipv4_addr";
          map = "verdict";
          comment = "per-host verdicts";
        };
      }
    );
    expectedError.msg = helpers.refusals.jsonIgnored "map comment";
  };

  # Without an address, nft's JSON parser fails on a NAT family other than
  # an ip table's, while text, which can't write the family, loads.
  testNatOtherFamilyPortOnlyRefused = {
    expr = toTextBlock (
      dsl.table "ip" "t" {
        chains.c.rules = [
          [
            (dsl.eq dsl.fields.meta.l4proto "tcp")
            (dsl.snat {
              family = "ip6";
              port = 1024;
            })
          ]
        ];
      }
    );
    expectedError.msg = helpers.refusals.noTextSpelling "nat family";
  };

  # nft's JSON parser also ignores element statements.
  testElementStatementRefused = {
    expr = toTextBlock (
      dsl.table "ip" "t" {
        sets.s = {
          type = "ipv4_addr";
          stmt = [ { counter = null; } ];
          elem = [
            {
              elem = {
                val = "10.0.0.1";
                counter = {
                  packets = 1;
                  bytes = 2;
                };
              };
            }
          ];
        };
      }
    );
    expectedError.msg = helpers.refusals.jsonIgnored "element counter";
  };

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
    expectedError.msg = "nix-nftypes: text: block-form text rendering expects one dsl\\.table node";
  };

  testRawChainCommandRejectedPretty = {
    expr = toTextBlockPretty {
      add.chain = {
        family = "inet";
        table = "fw";
        name = "input";
      };
    };
    expectedError.msg = "nix-nftypes: text: block-form text rendering expects one dsl\\.table node";
  };

  # Assertions cross the public table interface. The old internal command
  # envelope and its partition/regroup protocol no longer exist.
  testRulesetEnvelopeRejected = {
    expr = toTextBlock (dsl.ruleset [ (dsl.table "inet" "fw" { }) ]);
    expectedError.msg = "nix-nftypes: text: block-form text rendering expects one dsl\\.table node";
  };

  testTableListRejectedPretty = {
    expr = toTextBlockPretty [
      (dsl.table "inet" "fw" { })
      (dsl.table "inet" "other" { })
    ];
    expectedError.msg = "nix-nftypes: text: block-form text rendering expects one dsl\\.table node";
  };

  testUnknownTableKeyRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { chians.input = { }; });
    expectedError.msg = "nix-nftypes: dsl\\.table inet\\.fw: unsupported key.*chians";
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

  # The wrapper holds only the family and name: flags and comment stay in
  # the block, or a dormant table would load active. A handle has no
  # block-form spelling.
  testTableFlagsAndCommentStayInBlock = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        comment = "table";
        flags = [ "dormant" ];
        handle = 7;
      }
    );
    expected = "flags dormant;\ncomment \"table\";";
  };

  testTableFlagsAndCommentStayInBlockPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        comment = "table";
        flags = [ "dormant" ];
        chains.input = baseChain;
      }
    );
    expected = ''
      flags dormant;
      comment "table";
      chain input {
        type filter hook input priority 0;
      }'';
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

  # A rule loads through `add rule`, which takes no handle.
  testRuleHandleRejectedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          {
            expr = [ dsl.accept ];
            handle = 7;
          }
        ];
      }
    );
    expectedError.msg = "chains\\.input\\.rules\\.\"?0\"?\\.handle' does not exist";
  };

  # JSON and imperative text add the rule after the rule at its index,
  # while a chain block lists its rules in order.
  testRuleIndexRefusedCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          [ dsl.accept ]
          [ dsl.notrack ]
          {
            expr = [ dsl.drop ];
            index = 0;
          }
        ];
      }
    );
    expectedError.msg = helpers.refusals.noTextSpelling "rule index";
  };

  testRuleIndexRefusedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          {
            expr = [ dsl.accept ];
            index = 0;
            comment = "first";
          }
        ];
      }
    );
    expectedError.msg = helpers.refusals.noTextSpelling "rule index";
  };

  testInvalidNamedObjectRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { counters.hits.packets = "lots"; });
    expectedError.msg = "counters\\.hits\\.packets.*is not of type";
  };

  # Quoted, `010` is the name, not the number 8, and a `,` can't split
  # an element.
  testIfnameElementsQuotedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        sets.interfaces = {
          type = "ifname";
          elements = [
            "eth0,eth1"
            "010"
          ];
        };
      }
    );
    expected = ''
      set interfaces {
        type ifname;
        elements = { "eth0,eth1", "010" };
      }'';
  };

  testUnsafeIfnameElementRefusedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        sets.interfaces = {
          type = "ifname";
          elements = [ "eth/0" ];
        };
      }
    );
    expectedError.msg = helpers.refusals.ifname "set element";
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
    expectedError.msg = "nix-nftypes: text: block-form text rendering cannot embed standalone table elements";
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
    expectedError.msg = "nix-nftypes: text: block-form text rendering cannot embed standalone table elements";
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
                (dsl.counter {
                  packets = 1;
                  bytes = 2;
                })
                dsl.accept
              ];
              comment = "allow";
            }
          ];
        };
      }
    );
    expected = "chain input { counter packets 1 bytes 2 accept comment \"allow\"; }";
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
        chains.forward = (baseChain // { hook = "forward"; }) // {
          rules = [
            [ dsl.accept ]
            [ dsl.accept ]
          ];
        };
      }
    );
    expected = "chain forward { type filter hook forward priority 0; accept; accept; }";
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
      "chain service { ip saddr == @trusted counter name \"hits\" accept; drop; }"
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
        ip saddr == @trusted counter name "hits" accept;
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
