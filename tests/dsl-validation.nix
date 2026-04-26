{ lib, nftlib }:

# DSL-level validation tests. Each case constructs a DSL value with a
# clearly-invalid field and asserts that evaluation throws — proving the
# DSL surface routes user input through the matching schema submodule
# instead of letting type errors leak into the rendered JSON (where
# `nft -j -f` silently drops broken sections).
#
# Companion suite: tests/dsl-validation-messages.nix runs representative
# cases through `nix-instantiate --eval` and asserts the stderr names the
# offending path (e.g. "chains.c.prio: …"). This file checks the failure;
# that one checks the message format.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toJSON;

  # Force evaluation of the rendered JSON so the schema actually runs.
  # Without `toJSON` the table tree is just a marked attrset and no
  # evalModules call is triggered.
  renders = rulesetValue: (builtins.tryEval (toJSON (dsl.ruleset rulesetValue))).success;

  tests = {
    # The user's bug. Schema `chainBody.prio` is `nullOr int`; passing a
    # symbolic priority like "filter" used to render to `"prio":"filter"`
    # and the kernel silently dropped the base-chain attrs.
    testChainsCPrioStringRejected = {
      expr = renders [
        (dsl.table "inet" "t" {
          chains.c = {
            type = "filter";
            hook = "input";
            policy = "drop";
            prio = "filter";
          };
        })
      ];
      expected = false;
    };

    # ----- command-builder constructors (commands.nix) --------------------

    testCreateChainPrioStringRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.create.chain {
          family = "ip";
          table = "t";
          name = "c";
          prio = "filter";
        }))).success;
      expected = false;
    };

    testDeleteCounterBadFamilyRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.delete.counter {
          family = "wireguard";
          table = "t";
          name = "ctr";
        }))).success;
      expected = false;
    };

    testListMapBadTypeRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.list.map {
          family = "ip";
          table = "t";
          name = "m";
          type = 123;
        }))).success;
      expected = false;
    };

    testResetRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.reset.rule {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          handle = "not-a-number";
        }))).success;
      expected = false;
    };

    testRenameChainBadNewnameRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.rename.chain {
          family = "ip";
          table = "t";
          name = "c";
          newname = 42;
        }))).success;
      expected = false;
    };

    testReplaceRuleBadHandleRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.replace {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          handle = "abc";
        }))).success;
      expected = false;
    };

    testInsertRuleBadIndexRejected = {
      expr =
        (builtins.tryEval (toJSON (dsl.insert {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ ];
          index = -1;
        }))).success;
      expected = false;
    };
  };

  runTests =
    pkgs:
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs.runCommandLocal "dsl-validation-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} validation tests passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "dsl-validation-tests-fail" { } ''
        cat <<'EOF'
        DSL validation tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests;
}
