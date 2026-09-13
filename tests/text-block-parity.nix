{ pkgs, nftlib }:

# Parity tests for the block-form text renderer (toTextBlock /
# toTextBlockPretty).
#
# Each case asserts the exact emitted string for a `dsl.table` value.
# Mirrors tests/text-parity.nix's pattern but exercises the block-form
# path: no `add` keyword, no `<family> <table>` prefix on object
# headers, rules folded as inline statements inside their parent
# chain's brace block.
#
# The companion live-parser check (`runIntegrationTests`) wraps each
# case's output in `table <fam> <name> { ... }` and feeds it to
# `unshare -rn nft -c -f -` to verify the round-trip is accepted by
# the upstream nftables parser.

let
  inherit (pkgs) lib;
  inherit (nftlib)
    toTextBlock
    toTextBlockPretty
    dsl
    ;

  baseChain = {
    type = "filter";
    hook = "input";
    prio = 0;
  };

  tests = {
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
      expr =
        (builtins.tryEval (toTextBlock {
          add.table = {
            family = "inet";
            name = "fw";
          };
        })).success;
      expected = false;
    };

    testRawChainCommandRejectedPretty = {
      expr =
        (builtins.tryEval (toTextBlockPretty {
          add.chain = {
            family = "inet";
            table = "fw";
            name = "input";
          };
        })).success;
      expected = false;
    };

    # Assertions cross the public table interface. The old internal command
    # envelope and its partition/regroup protocol no longer exist.
    testRulesetEnvelopeRejected = {
      expr = (builtins.tryEval (toTextBlock (dsl.ruleset [ (dsl.table "inet" "fw" { }) ]))).success;
      expected = false;
    };

    testTableListRejectedPretty = {
      expr =
        (builtins.tryEval (toTextBlockPretty [
          (dsl.table "inet" "fw" { })
          (dsl.table "inet" "other" { })
        ])).success;
      expected = false;
    };

    testUnknownTableKeyRejected = {
      expr = (builtins.tryEval (toTextBlock (dsl.table "inet" "fw" { chians.input = { }; }))).success;
      expected = false;
    };

    # Omitting wrapper fields from output must not skip their validation,
    # including when there are no declarations to render.
    testInvalidEmptyTableFamilyRejected = {
      expr = (builtins.tryEval (toTextBlock (dsl.table "invalid" "fw" { }))).success;
      expected = false;
    };

    testInvalidEmptyTableFlagsRejectedPretty = {
      expr =
        (builtins.tryEval (toTextBlockPretty (dsl.table "inet" "fw" { flags = [ "invalid" ]; }))).success;
      expected = false;
    };

    testInvalidEmptyTableCommentRejected = {
      expr = (builtins.tryEval (toTextBlock (dsl.table "inet" "fw" { comment = 7; }))).success;
      expected = false;
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
      expr =
        (builtins.tryEval (
          toTextBlock (
            dsl.table "inet" "fw" {
              chains.input = baseChain // {
                prio = "filter";
              };
            }
          )
        )).success;
      expected = false;
    };

    testInvalidRuleHandleRejectedPretty = {
      expr =
        (builtins.tryEval (
          toTextBlockPretty (
            dsl.table "inet" "fw" {
              chains.input.rules = [
                {
                  expr = [ dsl.accept ];
                  handle = "invalid";
                }
              ];
            }
          )
        )).success;
      expected = false;
    };

    testInvalidNamedObjectRejected = {
      expr =
        (builtins.tryEval (toTextBlock (dsl.table "inet" "fw" { counters.hits.packets = "lots"; })))
        .success;
      expected = false;
    };

    testUnsafeIfnameElementRejectedPretty = {
      expr =
        (builtins.tryEval (
          toTextBlockPretty (
            dsl.table "inet" "fw" {
              sets.interfaces = {
                type = "ifname";
                elements = [ "eth0,eth1" ];
              };
            }
          )
        )).success;
      expected = false;
    };

    # Standalone `element` is an imperative command and has no legal form
    # inside a `table ... {}` block. Block renderers must reject this DSL tree
    # instead of emitting parser-invalid `element name { ... }` text.
    testStandaloneElementsRejectedCompact = {
      expr =
        (builtins.tryEval (
          toTextBlock (
            dsl.table "inet" "fw" {
              sets.blocked = {
                type = "ipv4_addr";
              };
              elements.blocked = {
                elements = [ "192.0.2.1" ];
              };
            }
          )
        )).success;
      expected = false;
    };

    testStandaloneElementsRejectedPretty = {
      expr =
        (builtins.tryEval (
          toTextBlockPretty (
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
          )
        )).success;
      expected = false;
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
      expected = ''
        chain input { type filter hook input priority 0; tcp dport vmap @dispatch; }
        chain service { ip saddr @trusted counter name "hits" accept; drop; }
        counter hits { }
        map dispatch { type inet_service : verdict; elements = { 22 : jump service }; }
        set trusted { type ipv4_addr; elements = { 192.0.2.1 }; }'';
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
      expected = ''
        chain input { limit rate over 10 kbytes/minute burst 5 bytes; limit name "slow" accept; }
        limit slow { rate 5/second burst 10 packets; comment "packet budget"; }'';
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
  };

  limitTable = dsl.table "inet" "fw" {
    chains.input.rules = [
      [
        (dsl.limit {
          rate = 10;
          per = "minute";
          inv = true;
          rate_unit = "kbytes";
          burst = 5;
          burst_unit = "bytes";
        })
      ]
      [
        (dsl.limit.ref "slow")
        dsl.accept
      ]
    ];
    limits.slow = {
      rate = 5;
      per = "second";
      burst = 10;
      comment = "packet budget";
    };
  };

  # Exercise references in both directions: chains use named objects,
  # and verdict-map elements refer back to a chain. Intentionally declare
  # fields out of output order; rules within service must keep source order.
  referencedTable = dsl.table "inet" "fw" {
    chains.service.rules = [
      [
        (dsl.inSet dsl.fields.ip.saddr "@trusted")
        (dsl.counter.ref "hits")
        dsl.accept
      ]
      [ dsl.drop ]
    ];
    chains.input = baseChain // {
      rules = [ [ (dsl.vmap dsl.fields.tcp.dport "@dispatch") ] ];
    };
    sets.trusted = {
      type = "ipv4_addr";
      elements = [ "192.0.2.1" ];
    };
    maps.dispatch = {
      type = "inet_service";
      map = "verdict";
      elements = [
        [
          22
          (dsl.jump "service")
        ]
      ];
    };
    counters.hits = { };
  };

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "nft-text-block-parity-tests";
    inherit tests;
  };

  # Live-parser cases: each `table` is rendered to block form, wrapped
  # in `table <family> <name> { ... }`, and piped through
  # `unshare -rn nft -c -f -` to verify the upstream parser accepts the
  # round-trip. Same harness shape as tests/text-integration.nix.
  integrationCases = [
    {
      name = "inline-and-named-limits";
      table = limitTable;
    }
    {
      name = "chain-object-references";
      table = referencedTable;
    }
    {
      name = "minimal-base-chain";
      table = dsl.table "inet" "fw" { chains.input = baseChain; };
    }
    {
      name = "chain-with-rules";
      table = dsl.table "inet" "fw" {
        chains.input = baseChain // {
          policy = "drop";
          rules = [
            [ dsl.accept ]
            [ dsl.drop ]
          ];
        };
      };
    }
    {
      name = "mixed-chain-set-counter";
      table = dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [ [ dsl.accept ] ];
        };
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
        counters.hits = { };
      };
    }
    {
      name = "set-with-inline-elements";
      table = dsl.table "inet" "fw" {
        sets.blocked = {
          type = "ipv4_addr";
          elements = [ "192.0.2.1" ];
        };
      };
    }
  ];

  runIntegrationTests =
    pkgs': cases:
    let
      caseForms = lib.concatMap (c: [
        {
          inherit (c) name table;
          form = "pretty";
          rendered = toTextBlockPretty c.table;
        }
        {
          inherit (c) name table;
          form = "compact";
          rendered = toTextBlock c.table;
        }
      ]) cases;
    in
    pkgs'.runCommandLocal "text-block-integration-tests"
      {
        nativeBuildInputs = [
          pkgs'.nftables
          pkgs'.util-linux
        ];
      }
      ''
        set +e
        failed=0
        ${lib.concatMapStringsSep "\n" (cf: ''
            printf '=== %s (%s) ===\n' ${lib.escapeShellArg cf.name} ${cf.form}
            inner=$(cat <<'INNER_EOF'
          ${cf.rendered}
          INNER_EOF
            )
            ruleset="table ${cf.table.family} ${cf.table.name} {
          $inner
          }"
            if nft_err=$(unshare -rn nft -c -f - <<<"$ruleset" 2>&1); then
              echo "PASS"
            else
              echo "FAIL:"
              echo "$nft_err" | sed 's/^/    /'
              echo "$ruleset" | sed 's/^/    | /'
              failed=$((failed + 1))
            fi
        '') caseForms}
        if [ "$failed" -gt 0 ]; then
          echo "$failed text-block-integration test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length caseForms)} text-block-integration tests passed"
        touch $out
      '';
in
{
  inherit
    tests
    runTests
    integrationCases
    runIntegrationTests
    ;
}
