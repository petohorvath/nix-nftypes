{
  helpers,
  lib,
  nftlib,
  ...
}:

# Regression coverage for the named-reference injection class.
# Three statement kinds carry an `@<name>` reference to a pre-declared
# object, rendered bare into the output:
#
#   set    statement → `<op> @<set>  { … }`
#   map    statement → `<op> @<map>  { … }`
#   flow   statement → `flow <op> @<flowtable>`
#
# Pre-fix, an unsafe byte in the name truncated the statement and
# dropped a fresh `add chain` payload into the rendered text that
# `nft -f` parsed as a real chain at attacker-chosen priority.
#
# Renderer-level fix: each reference flows through `namedReference`
# (lib/text/primitives.nix), which refuses one without its `@` and
# checks the name with `safeToken`. The shared `nft-safe-scalar`
# predicate accepts the identifier-shaped subset of bytes legitimate
# object names use; it rejects whitespace, nft-grammar
# metacharacters, and control characters.

let
  inherit (nftlib) dsl toTextPretty;

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
                element = "1.2.3.4";
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
                key = "1.2.3.4";
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
        chains.c = {
          type = "filter";
          hook = "forward";
          prio = 0;
          rules = [
            [
              (dsl.flow name)
            ]
          ];
        };
      })
    ];

  # The DSL adds the `@` a name lacks.
  surfaces = {
    setStmt = rulesetSetStmt;
    mapStmt = rulesetMapStmt;
    flow = rulesetFlow;
  };

  # Field label each surface's renderer names in its refusal.
  fieldOf = {
    setStmt = "set reference";
    mapStmt = "map reference";
    flow = "flowtable reference";
  };

  refusal = helpers.refusals.bareToken;

  badInputs = {
    newline = "blocked\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "blocked; add chain inet fw pwned;";
    brace = "blocked}";
    quote = ''blocked"'';
    backslash = ''blocked\'';
    space = "blocked extra";
    hash = "blocked#";
    comma = "blocked,extra";
  };

  goodInputs = {
    bareName = "blocked";
    atPrefixed = "@blocked";
    withDigits = "blocked_v4";
    withHyphen = "block-list";
    withDot = "v4.list";
  };

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toText (surfaces.${surface} badValue);
          expectedError.msg = refusal fieldOf.${surface};
        };
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

  # Pin the safe inputs against the compact renderer.
  acceptanceTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (goodName: goodValue: {
        name = "testRendererAccepts_${surface}_${goodName}";
        value = {
          expr = builtins.isString (nftlib.toText (surfaces.${surface} goodValue));
          expected = true;
        };
      }) goodInputs
    ) (builtins.attrNames surfaces)
  );

  prettyTests = {
    testPrettyRejects_setStmt_newline = {
      expr = toTextPretty (rulesetSetStmt badInputs.newline);
      expectedError.msg = refusal "set reference";
    };
    testPrettyRejects_mapStmt_newline = {
      expr = toTextPretty (rulesetMapStmt badInputs.newline);
      expectedError.msg = refusal "map reference";
    };
    testPrettyRejects_flow_newline = {
      expr = toTextPretty (rulesetFlow badInputs.newline);
      expectedError.msg = refusal "flowtable reference";
    };
  };

  # Raw statements bypass the DSL and the schema, so the renderer
  # refuses a reference without its `@`, or with no name after it.
  rawRule = statement: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "fw";
          chain = "input";
          expr = [ statement ];
        };
      }
    ];
  };
  rawStatements = reference: {
    setStmt.set = {
      op = "add";
      elem = "1.2.3.4";
      set = reference;
    };
    mapStmt.map = {
      op = "update";
      elem = "1.2.3.4";
      data = 1;
      map = reference;
    };
    flow.flow = {
      op = "add";
      flowtable = reference;
    };
  };
  rawTests =
    lib.mapAttrs' (surface: statement: {
      name = "testRendererRejectsWithoutAt_${surface}";
      value = {
        expr = nftlib.toText (rawRule statement);
        expectedError.msg = helpers.refusals.namedReference fieldOf.${surface};
      };
    }) (rawStatements "blocked")
    // lib.mapAttrs' (surface: statement: {
      name = "testRendererRejectsEmptyName_${surface}";
      value = {
        expr = nftlib.toText (rawRule statement);
        expectedError.msg = refusal fieldOf.${surface};
      };
    }) (rawStatements "@");
in
rejectionTests // acceptanceTests // prettyTests // rawTests
