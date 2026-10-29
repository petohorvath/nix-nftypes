{
  fixtures,
  helpers,
  internal,
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
  inherit (helpers) capitalise;
  inherit (nftlib)
    dsl
    toTextBlock
    toTextBlockPretty
    ;

  /*
    A Table tree adds its objects, and nft ignores a handle on add, so
    neither block form takes one: the table, a chain, a rule, or a named
    object.
  */
  handleRejectedTests =
    let
      cases = {
        table = {
          body.handle = 7;
          at = "handle";
        };
        chain = {
          body.chains.input.handle = 7;
          at = "chains\\.input\\.handle";
        };
        rule = {
          body.chains.input.rules = [
            {
              statements = [ dsl.accept ];
              handle = 7;
            }
          ];
          at = "chains\\.input\\.rules\\.0\\.handle";
        };
        counter = {
          body.counters.hits.handle = 7;
          at = "counters\\.hits\\.handle";
        };
      };
    in
    lib.concatMapAttrs (
      name: case:
      lib.mapAttrs'
        (
          renderer: render:
          lib.nameValuePair "test${capitalise name}HandleRejected${renderer}" {
            expr = render (dsl.table "inet" "fw" case.body);
            expectedError.msg = "nix-nftypes: dsl\\.table inet\\.fw: ${case.at}: nft ignores a handle on add.*Read-back";
          }
        )
        {
          Compact = toTextBlock;
          Pretty = toTextBlockPretty;
        }
    ) cases;
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
          dataType = "verdict";
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
          statements = [ { counter = null; } ];
          elements = [
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

  # Block renderers accept only Table trees. Raw commands must not be
  # silently discarded or rendered without their table context, and the
  # error says what the renderer got and points to `toText`.
  testRawTableCommandRejected = {
    expr = toTextBlock {
      add.table = {
        family = "inet";
        name = "fw";
      };
    };
    expectedError.msg = "^nix-nftypes: toTextBlock: expected one Table tree from `dsl\\.table`, got an attribute set with add; render a ruleset with `toText`$";
  };

  testRawChainCommandRejectedPretty = {
    expr = toTextBlockPretty {
      add.chain = {
        family = "inet";
        table = "fw";
        name = "input";
      };
    };
    expectedError.msg = "^nix-nftypes: toTextBlockPretty: expected one Table tree from `dsl\\.table`, got an attribute set with add; render a ruleset with `toText`$";
  };

  # Assertions cross the public table interface. The old internal command
  # envelope and its partition/regroup protocol no longer exist.
  testRulesetEnvelopeRejected = {
    expr = toTextBlock (dsl.ruleset [ (dsl.table "inet" "fw" { }) ]);
    expectedError.msg = "^nix-nftypes: toTextBlock: expected one Table tree from `dsl\\.table`, got a ruleset; render a ruleset with `toText`$";
  };

  testTableListRejectedPretty = {
    expr = toTextBlockPretty [
      (dsl.table "inet" "fw" { })
      (dsl.table "inet" "other" { })
    ];
    expectedError.msg = "^nix-nftypes: toTextBlockPretty: expected one Table tree from `dsl\\.table`, got a list; render a ruleset with `toText`$";
  };

  testUnknownTableKeyRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { chians.input = { }; });
    expectedError.msg = "nix-nftypes: dsl\\.table inet\\.fw: unsupported key.*chians";
  };

  # A wrongly shaped `chains` or rule list names the table and its path.
  testChainsListRejected = {
    expr = toTextBlock (dsl.table "inet" "fw" { chains = [ ]; });
    expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains: expected an attribute set of chain bodies, got a list$";
  };

  testRulesSetRejectedPretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { chains.input.rules = { }; });
    expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules: expected a list of rules, got a set$";
  };

  # Omitting wrapper fields from output must not skip their validation,
  # including when there are no declarations to render.
  testInvalidEmptyTableFamilyRejected = {
    expr = toTextBlock (dsl.table "invalid" "fw" { });
    expectedError.msg = "option `\"?dsl\\.table invalid\\.fw\"?\\.family' is not of type";
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
  # the block, or a dormant table would load active.
  testTableFlagsAndCommentStayInBlock = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        comment = "table";
        flags = [ "dormant" ];
      }
    );
    expected = "flags dormant;\ncomment \"table\";\n";
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
      }
    '';
  };

  # A Symbolic priority nft rejects at the chain's hook throws.
  testInvalidChainPriorityRejected = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          prio = "dstnat";
        };
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.prio: family 'inet' has no priority 'dstnat' at hook 'input'";
  };

  # A Table tree lists a chain's rules in order and takes no rule
  # `index`, so a tree renders in both forms; block form throws as
  # `dsl.ruleset` does.
  testRuleIndexRejectedCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          [ dsl.accept ]
          [ dsl.notrack ]
          {
            statements = [ dsl.drop ];
            index = 0;
          }
        ];
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules\\.2\\.index: a Table tree lists a chain's rules in order, so a rule takes no `index`";
  };

  testRuleIndexRejectedPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input.rules = [
          {
            statements = [ dsl.accept ];
            index = 0;
            comment = "first";
          }
        ];
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules\\.0\\.index: a Table tree lists a chain's rules in order, so a rule takes no `index`";
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
      }
    '';
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

  # ---- chain only (base chain, no rules) -----------------------------
  testBaseChainNoRulesCompact = {
    expr = toTextBlock (dsl.table "inet" "fw" { chains.input = baseChain; });
    expected = "chain input { type filter hook input priority 0; }\n";
  };

  testBaseChainNoRulesPretty = {
    expr = toTextBlockPretty (dsl.table "inet" "fw" { chains.input = baseChain; });
    expected = ''
      chain input {
        type filter hook input priority 0;
      }
    '';
  };

  # A Symbolic priority renders as the int it resolves to for the chain's
  # family and hook: a bridge chain's `filter` is -200.
  testSymbolicPriorityRendersInt = {
    expr = toTextBlock (
      dsl.table "bridge" "br" {
        chains.input = baseChain // {
          prio = "filter";
        };
      }
    );
    expected = "chain input { type filter hook input priority -200; }\n";
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
    expected = "chain input { type filter hook input priority 0; policy drop; accept; drop; }\n";
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
      }
    '';
  };

  # ---- rule with comment ---------------------------------------------
  testChainRuleWithCommentPretty = {
    expr = toTextBlockPretty (
      dsl.table "inet" "fw" {
        chains.input = baseChain // {
          rules = [
            {
              statements = [ dsl.accept ];
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
      }
    '';
  };

  testMatchingScopeAndCleanedRule = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
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
              statements = [
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
    expected = "chain input { counter packets 1 bytes 2 accept comment \"allow\"; }\n";
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
    expected = "set lan_v4 { type ipv4_addr; flags interval; }\n";
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
      }
    '';
  };

  testCounterBlockCompact = {
    expr = toTextBlock (
      dsl.table "inet" "fw" {
        counters.hits = { };
      }
    );
    expected = "counter hits { }\n";
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
    expected = "chain forward { type filter hook forward priority 0; accept; accept; }\n";
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
    expected = "chain input { type filter hook input priority 0; accept; }\nset lan_v4 { type ipv4_addr; flags interval; }\n";
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
      }
    '';
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
      }
    '';
  };

  testReferencesAndOrderingCompact = {
    expr = toTextBlock referencedTable;
    expected = lib.concatStrings [
      "chain input { type filter hook input priority 0; tcp dport vmap @dispatch; }\n"
      "chain service { ip saddr == @trusted counter name \"hits\" accept; drop; }\n"
      "counter hits { }\n"
      "map dispatch { type inet_service : verdict; elements = { 22 : jump service }; }\n"
      "set trusted { type ipv4_addr; elements = { 192.0.2.1 }; }\n"
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
      }
    '';
  };

  testLimitsCompact = {
    expr = toTextBlock limitTable;
    expected = lib.concatStrings [
      "chain input { limit rate over 10 kbytes/minute burst 5 bytes; limit name \"slow\" accept; }\n"
      "limit slow { rate 5/second burst 10 packets; comment \"packet budget\"; }\n"
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
      }
    '';
  };
}
# A kind's wrongly shaped named objects name the table and the kind's key
# in block form too, for every kind a table tree holds.
// lib.concatMapAttrs (
  _:
  { plural, tag, ... }:
  {
    "test${capitalise plural}ListRejected" = {
      expr = toTextBlock (dsl.table "inet" "fw" { ${plural} = [ ]; });
      expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: ${plural}: expected an attribute set of ${tag} bodies, got a list$";
    };
  }
) internal.dslObjectKinds
// handleRejectedTests
