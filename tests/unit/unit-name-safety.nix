{
  helpers,
  lib,
  nftlib,
  ...
}:

# Regression coverage for the limit/quota unit-name injection class.
# `limit` and `quota` carry `rate_unit`, `burst_unit`, `val_unit`, and
# `used_unit` fields (`rateUnit`, … in the DSL), which the renderer emits
# bare into the surrounding clause:
#
#   limit rate <N> <rate_unit>/<per> burst <N> <burst_unit>
#   quota [over] <N> <val_unit> used <N> <used_unit>
#
# When the schema typed them `types.str`, a value carrying a newline +
# `add chain …` truncated the clause and dropped a fresh chain into the
# rendered file — accepted by `nft -f` as a real chain at
# attacker-chosen priority.
#
# The schema now takes only nft's units (`limitRateUnit`, `byteUnit`),
# so each surface below is a Raw attrset, which reaches the renderer
# unvalidated (ADR 0003). Limit statements, named objects, and
# positional `create` commands share lib/text/limit.nix. Limit and quota
# units pass through `safeToken` / the shared `nft-safe-scalar`
# predicate.

let
  inherit (nftlib) toTextPretty;

  # A rule in inet fw input holding `statement`, then accept.
  rawRule = statement: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "fw";
          chain = "input";
          expr = [
            statement
            { accept = null; }
          ];
        };
      }
    ];
  };

  rulesetLimitStmt =
    field: value:
    rawRule {
      limit = {
        rate = 1;
        per = "second";
        burst = 5;
        ${field} = value;
      };
    };

  rulesetQuotaStmt =
    field: value:
    rawRule {
      quota = {
        val = 100;
        used = 50;
        ${field} = value;
      };
    };

  # The named limit `fast`, added or created.
  rawLimitObject = verb: field: value: {
    nftables = [
      {
        ${verb}.limit = {
          family = "inet";
          table = "fw";
          name = "fast";
          rate = 10;
          per = "second";
          burst = 5;
          ${field} = value;
        };
      }
    ];
  };

  rulesetLimitObject = rawLimitObject "add";

  rulesetCreateLimit = rawLimitObject "create";

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

  # Field label each surface's renderer names in its refusal.
  fieldOf = {
    limitStmt_rate_unit = "limit rate_unit";
    limitStmt_burst_unit = "limit burst_unit";
    quotaStmt_val_unit = "quota val_unit";
    quotaStmt_used_unit = "quota used_unit";
    limitObject_rate_unit = "limit rate_unit";
    limitObject_burst_unit = "limit burst_unit";
    createLimit_rate_unit = "limit rate_unit";
    createLimit_burst_unit = "limit burst_unit";
  };

  refusal = helpers.refusals.bareToken;

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
          expectedError.msg = refusal fieldOf.${surface};
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
      expectedError.msg = refusal "limit rate_unit";
    };
    testPrettyRejects_limitObject_burst_unit_newline = {
      expr = toTextPretty (rulesetLimitObject "burst_unit" badInputs.newline);
      expectedError.msg = refusal "limit burst_unit";
    };
    testPrettyRejects_createLimit_burst_unit_newline = {
      expr = toTextPretty (rulesetCreateLimit "burst_unit" badInputs.newline);
      expectedError.msg = refusal "limit burst_unit";
    };
  };
in
rejectionTests // acceptanceTests // prettyTests
