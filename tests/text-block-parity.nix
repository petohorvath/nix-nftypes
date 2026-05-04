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

    # ---- chain only (base chain, no rules) -----------------------------
    testBaseChainNoRulesCompact = {
      expr = toTextBlock (dsl.table "inet" "fw" { chains.input = baseChain; });
      expected = "chain input { type filter hook input priority 0 }";
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
      expected = "chain input { type filter hook input priority 0; policy drop; accept; drop }";
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
      expected = "set lan_v4 { type ipv4_addr; flags interval }";
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

  runTests =
    pkgs':
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs'.runCommandLocal "nft-text-block-parity-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} text-block-parity tests passed"
        touch $out
      ''
    else
      pkgs'.runCommandLocal "nft-text-block-parity-tests-fail" { } ''
        cat <<'EOF'
        Text-block-parity tests failed:
        ${fmt results}
        EOF
        exit 1
      '';

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
  ];

  runIntegrationTests =
    pkgs': cases:
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
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}
          inner=$(cat <<'INNER_EOF'
          ${toTextBlockPretty c.table}
          INNER_EOF
          )
          ruleset="table ${c.table.family} ${c.table.name} {
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
        '') cases}
        if [ "$failed" -gt 0 ]; then
          echo "$failed text-block-integration test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length cases)} text-block-integration tests passed"
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
