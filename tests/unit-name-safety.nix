{ lib, nftlib }:

# Regression coverage for the limit/quota unit-name injection class.
# `limit` and `quota` carry `rate_unit`, `burst_unit`, `val_unit`,
# `used_unit` fields typed `types.str` in the schema. The renderer
# emitted each bare into the surrounding clause:
#
#   limit rate <N> <rate_unit>/<per> burst <N> <burst_unit>
#   quota [over] <N> <val_unit> used <N> <used_unit>
#
# A value carrying a newline + `add chain …` truncated the clause and
# dropped a fresh chain into the rendered file — accepted by `nft -f`
# as a real chain at attacker-chosen priority.
#
# The renderer (statement form in lib/text/statements.nix, object form
# in lib/text/objects.nix, positional `create` form in
# lib/text/commands.nix) now routes each unit name through `safeToken`
# / the shared `nft-safe-scalar` predicate.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toText toTextPretty;

  evalSucceeds = expr: (builtins.tryEval expr).success;

  rulesetLimitStmt =
    field: value:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.limit (
                {
                  rate = 1;
                  per = "second";
                  burst = 5;
                }
                // {
                  ${field} = value;
                }
              ))
              dsl.accept
            ]
          ];
        };
      })
    ];

  rulesetQuotaStmt =
    field: value:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.quota (
                {
                  val = 100;
                  used = 50;
                }
                // {
                  ${field} = value;
                }
              ))
              dsl.accept
            ]
          ];
        };
      })
    ];

  rulesetLimitObject =
    field: value:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        limits.fast = {
          rate = 10;
          per = "second";
          burst = 5;
          ${field} = value;
        };
      })
    ];

  surfaces = {
    limitStmt_rate_unit = rulesetLimitStmt "rate_unit";
    limitStmt_burst_unit = rulesetLimitStmt "burst_unit";
    quotaStmt_val_unit = rulesetQuotaStmt "val_unit";
    quotaStmt_used_unit = rulesetQuotaStmt "used_unit";
    limitObject_rate_unit = rulesetLimitObject "rate_unit";
    limitObject_burst_unit = rulesetLimitObject "burst_unit";
  };

  badInputs = {
    newline = "packets\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "packets; add chain inet fw pwned;";
    brace = "packets}";
    quote = ''packets"'';
    backslash = ''packets\'';
    space = "packets extra";
    hash = "packets#";
    comma = "packets,extra";
    empty = "";
  };

  goodInputs = {
    packets = "packets";
    bytes = "bytes";
    kbytes = "kbytes";
    mbytes = "mbytes";
    gbytes = "gbytes";
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
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

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
    testPrettyRejects_limitStmt_rate_unit_newline = {
      expr = evalSucceeds (toTextPretty (rulesetLimitStmt "rate_unit" badInputs.newline));
      expected = false;
    };
    testPrettyRejects_limitObject_burst_unit_newline = {
      expr = evalSucceeds (toTextPretty (rulesetLimitObject "burst_unit" badInputs.newline));
      expected = false;
    };
  };

  # Positional `create.limit` is the third surface (separate code path
  # in lib/text/commands.nix). Exercise it through the dsl.create.limit
  # entry so the cmd-renderer's `safeToken` wiring is pinned.
  rulesetCreateLimit =
    field: value:
    dsl.ruleset [
      (dsl.create.limit {
        family = "inet";
        table = "fw";
        name = "fast";
        rate = 10;
        per = "second";
        ${field} = value;
      })
    ];

  createTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_createLimit_rate_unit_${badName}";
      value = {
        expr = rendererRejects (rulesetCreateLimit "rate_unit" badValue);
        expected = true;
      };
    }) badInputs
  );

  tests = rejectionTests // acceptanceTests // prettyTests // createTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "unit-name-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
