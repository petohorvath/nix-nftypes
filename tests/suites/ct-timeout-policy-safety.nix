{
  helpers,
  lib,
  nftlib,
  ...
}:

# Regression coverage for the ct-timeout policy-key injection class.
# `ctTimeout` named objects carry `policy` typed `attrsOf
# ints.unsigned`, so keys are arbitrary user strings. The renderer
# emitted them bare into `policy = { <k>: <v>, … }`; a key carrying
# `…}\nadd chain inet fw pwned { … }` closed the clause early and
# dropped a fresh `add chain` into the rendered text, accepted by
# `nft -f` as a real chain at attacker-chosen priority.
#
# Renderer-level fix: each key flows through `safeToken` (shared
# `nft-safe-scalar` predicate). Legitimate connection-state names
# (`established`, `close_wait`, `time_wait`, `last_ack`, …) are
# identifier-shaped and pass cleanly.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toTextPretty;

  rulesetWithPolicyKey =
    key:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        ctTimeouts.myto = {
          protocol = "tcp";
          l3proto = "ip";
          policy = {
            ${key} = 100;
          };
        };
      })
    ];

  refusal = helpers.refusals.bareToken "ct timeout policy key";

  badInputs = {
    newline = "established: 300 }\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }\n# foo";
    semicolon = "established;";
    brace = "established}";
    quote = ''established"'';
    backslash = ''established\'';
    space = "established extra";
    hash = "established#";
    comma = "established,extra";
    empty = "";
  };

  goodInputs = {
    established = "established";
    closeWait = "close_wait";
    timeWait = "time_wait";
    lastAck = "last_ack";
    finWait = "fin_wait";
  };

  rejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_${badName}";
      value = {
        expr = nftlib.toText (rulesetWithPolicyKey badValue);
        expectedError.msg = refusal;
      };
    }) badInputs
  );

  acceptanceTests = lib.listToAttrs (
    lib.mapAttrsToList (goodName: goodValue: {
      name = "testRendererAccepts_${goodName}";
      value = {
        expr = builtins.isString (nftlib.toText (rulesetWithPolicyKey goodValue));
        expected = true;
      };
    }) goodInputs
  );

  prettyTests = {
    testPrettyRejectsInjection = {
      expr = toTextPretty (rulesetWithPolicyKey badInputs.newline);
      expectedError.msg = refusal;
    };
    testPrettyAcceptsCleanKey = {
      expr = builtins.isString (toTextPretty (rulesetWithPolicyKey "established"));
      expected = true;
    };
  };
in
rejectionTests // acceptanceTests // prettyTests
