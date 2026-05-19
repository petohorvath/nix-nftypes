{ lib, nftlib }:

# Regression coverage for the named-reference injection class.
# Three statement kinds carry a `types.str` field that names a
# pre-declared object, rendered bare into the output:
#
#   set    statement → `<op> @<set>  { … }`     (renderer prepends `@`)
#   map    statement → `<op> @<map>  { … }`     (renderer prepends `@`)
#   flow   statement → `flow <op> <flowtable>`  (`@` carried by the value)
#
# Pre-fix, an unsafe byte in the name truncated the statement and
# dropped a fresh `add chain` payload into the rendered text that
# `nft -f` parsed as a real chain at attacker-chosen priority.
#
# Renderer-level fix: each name now flows through `safeToken`
# (lib/text/expressions.nix) before reaching the output. The shared
# `nft-safe-scalar` predicate accepts `@` and the identifier-shaped
# subset of bytes legitimate object names use; it rejects whitespace,
# nft-grammar metacharacters, and control characters.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toText toTextPretty;

  evalSucceeds = expr: (builtins.tryEval expr).success;

  rulesetSetStmt =
    name:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.setStmt {
                op = "add";
                elem = "1.2.3.4";
                set = name;
              })
            ]
          ];
        };
      })
    ];

  rulesetMapStmt =
    name:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.mapStmt {
                op = "update";
                elem = "1.2.3.4";
                data = 1;
                map = name;
              })
            ]
          ];
        };
      })
    ];

  rulesetFlow =
    name:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.fwd = {
          type = "filter";
          hook = "forward";
          prio = 0;
          rules = [
            [
              (dsl.flow {
                op = "add";
                flowtable = name;
              })
            ]
          ];
        };
      })
    ];

  surfaces = {
    setStmt = rulesetSetStmt;
    mapStmt = rulesetMapStmt;
    # `flowAt` constructs `@${name}` so an empty name yields a bare `@`
    # — still non-empty per the predicate (it's the `@` byte). The
    # `flowBare` surface omits the prefix so the empty-string case
    # exercises the predicate's non-empty assertion.
    flowAt = name: rulesetFlow "@${name}";
    flowBare = rulesetFlow;
  };

  # `empty` is in the `flowBare`-only set: for `flowAt` it pairs with
  # the `@` prefix and produces a non-empty (but malformed) value, so
  # the predicate accepts it and nft itself rejects at parse time.
  badInputsCommon = {
    newline = "blocked\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "blocked; add chain inet fw pwned;";
    brace = "blocked}";
    quote = ''blocked"'';
    backslash = ''blocked\'';
    space = "blocked extra";
    hash = "blocked#";
    comma = "blocked,extra";
  };
  badInputsBare = badInputsCommon // {
    empty = "";
  };
  badInputsForSurface = surface: if surface == "flowAt" then badInputsCommon else badInputsBare;

  goodInputs = {
    bareName = "blocked";
    atPrefixed = "@blocked";
    withDigits = "blocked_v4";
    withHyphen = "block-list";
    withDot = "v4.list";
  };

  rendererRejects = body: !(evalSucceeds (toText body));

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = rendererRejects (surfaces.${surface} badValue);
          expected = true;
        };
      }) (badInputsForSurface surface)
    ) (builtins.attrNames surfaces)
  );

  # Pin the safe inputs against compact and pretty renderers. The
  # `flowAt`/`flowBare` split isolates the `@`-prefix question from
  # the byte-safety question.
  acceptanceTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (goodName: goodValue: {
        name = "testRendererAccepts_${surface}_${goodName}";
        value = {
          expr = rendererRejects (surfaces.${surface} goodValue);
          expected = false;
        };
      }) goodInputs
    ) (builtins.attrNames surfaces)
  );

  prettyTests = {
    testPrettyRejects_setStmt_newline = {
      expr = evalSucceeds (toTextPretty (rulesetSetStmt badInputsCommon.newline));
      expected = false;
    };
    testPrettyRejects_mapStmt_newline = {
      expr = evalSucceeds (toTextPretty (rulesetMapStmt badInputsCommon.newline));
      expected = false;
    };
    testPrettyRejects_flow_newline = {
      expr = evalSucceeds (toTextPretty (rulesetFlow "@${badInputsCommon.newline}"));
      expected = false;
    };
  };

  tests = rejectionTests // acceptanceTests // prettyTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "named-ref-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
