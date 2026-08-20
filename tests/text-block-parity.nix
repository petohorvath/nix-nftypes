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
  # Exercise the internal envelope renderer directly as a defence-in-depth
  # boundary. Public callers go through lib/default.nix's stricter dsl.table
  # wrapper, but the internal contract also promises one add.table command and
  # no standalone element commands for hand-built envelopes.
  internalText = import ../lib/text {
    inherit lib;
    clean = import ../lib/clean.nix { inherit lib; };
    nftSafeString = import ../lib/nft-safe-string.nix { };
    nftSafeIfname = import ../lib/nft-safe-ifname.nix { };
    nftSafeScalar = import ../lib/nft-safe-scalar.nix { };
  };

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

    # The lower-level envelope renderer has the same structural boundary. These
    # tests bypass the public dsl.table wrapper so its checks cannot mask an
    # internal regression.
    testInternalEnvelopeSingleTableAccepted = {
      expr = internalText.toTextBlock {
        nftables = [
          {
            add.table = {
              family = "inet";
              name = "fw";
            };
          }
        ];
      };
      expected = "";
    };

    testInternalEnvelopeWithoutTableRejected = {
      expr =
        (builtins.tryEval (
          internalText.toTextBlock {
            nftables = [
              {
                add.chain = {
                  family = "inet";
                  table = "fw";
                  name = "input";
                };
              }
            ];
          }
        )).success;
      expected = false;
    };

    testInternalEnvelopeWithMultipleTablesRejected = {
      expr =
        (builtins.tryEval (
          internalText.toTextBlock {
            nftables = [
              {
                add.table = {
                  family = "inet";
                  name = "fw";
                };
              }
              {
                add.table = {
                  family = "inet";
                  name = "other";
                };
              }
            ];
          }
        )).success;
      expected = false;
    };

    testInternalEnvelopeWithStandaloneElementRejected = {
      expr =
        (builtins.tryEval (
          internalText.toTextBlock {
            nftables = [
              {
                add.table = {
                  family = "inet";
                  name = "fw";
                };
              }
              {
                add.element = {
                  family = "inet";
                  table = "fw";
                  name = "blocked";
                  elem = [ "192.0.2.1" ];
                };
              }
            ];
          }
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
