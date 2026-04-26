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
