{
  lib,
  nftlib,
  ...
}:

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
# Limit statements, named objects, and positional `create` commands share
# lib/text/limit.nix. Limit and quota units pass through `safeToken` /
# the shared `nft-safe-scalar` predicate.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toTextPretty;

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

  rulesetCreateLimit =
    field: value:
    dsl.ruleset [
      (dsl.create.limit {
        family = "inet";
        table = "fw";
        name = "fast";
        rate = 10;
        per = "second";
        burst = 5;
        ${field} = value;
      })
    ];

  surfaces = {
    limitStmt_rate_unit = rulesetLimitStmt "rate_unit";
    limitStmt_burst_unit = rulesetLimitStmt "burst_unit";
    quotaStmt_val_unit = rulesetQuotaStmt "val_unit";
    quotaStmt_used_unit = rulesetQuotaStmt "used_unit";
    limitObject_rate_unit = rulesetLimitObject "rate_unit";
    limitObject_burst_unit = rulesetLimitObject "burst_unit";
    createLimit_rate_unit = rulesetCreateLimit "rate_unit";
    createLimit_burst_unit = rulesetCreateLimit "burst_unit";
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

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toText (surfaces.${surface} badValue);
          expectedError.msg = "refusing to render a bare nft token";
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
          expr = builtins.isString (nftlib.toText (surfaces.${surface} goodValue));
          expected = true;
        };
      }) goodInputs
    ) (builtins.attrNames surfaces)
  );

  prettyTests = {
    testPrettyRejects_limitStmt_rate_unit_newline = {
      expr = toTextPretty (rulesetLimitStmt "rate_unit" badInputs.newline);
      expectedError.msg = "refusing to render a bare nft token";
    };
    testPrettyRejects_limitObject_burst_unit_newline = {
      expr = toTextPretty (rulesetLimitObject "burst_unit" badInputs.newline);
      expectedError.msg = "refusing to render a bare nft token";
    };
    testPrettyRejects_createLimit_burst_unit_newline = {
      expr = toTextPretty (rulesetCreateLimit "burst_unit" badInputs.newline);
      expectedError.msg = "refusing to render a bare nft token";
    };
  };
in
rejectionTests // acceptanceTests // prettyTests
