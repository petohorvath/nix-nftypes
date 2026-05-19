{ lib, nftlib }:

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
  inherit (nftlib) toText toTextPretty;

  evalSucceeds = expr: (builtins.tryEval expr).success;

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

  rendererRejects = body: !(evalSucceeds (toText body));

  rejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_${badName}";
      value = {
        expr = rendererRejects (rulesetWithPolicyKey badValue);
        expected = true;
      };
    }) badInputs
  );

  acceptanceTests = lib.listToAttrs (
    lib.mapAttrsToList (goodName: goodValue: {
      name = "testRendererAccepts_${goodName}";
      value = {
        expr = rendererRejects (rulesetWithPolicyKey goodValue);
        expected = false;
      };
    }) goodInputs
  );

  prettyTests = {
    testPrettyRejectsInjection = {
      expr = evalSucceeds (toTextPretty (rulesetWithPolicyKey badInputs.newline));
      expected = false;
    };
    testPrettyAcceptsCleanKey = {
      expr = evalSucceeds (toTextPretty (rulesetWithPolicyKey "established"));
      expected = true;
    };
  };

  tests = rejectionTests // acceptanceTests // prettyTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "ct-timeout-policy-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
