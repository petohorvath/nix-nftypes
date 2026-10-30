/*
  nix-unit entry point for the unit suites, which need only evaluation.
  Groups each suite's tests under the suite's file name. The suites that
  assert on probe records are in ../integration.

  nix-unit's flake-parts module runs it as `tests.systems.<system>.unit`
  (dev/default.nix).
*/
{ nixpkgs }:
let
  testContext = import ../test-context.nix { inherit nixpkgs; };
in
{
  comment-safety = import ./comment-safety.nix testContext;
  ct-timeout-policy-safety = import ./ct-timeout-policy-safety.nix testContext;
  dsl-parity = import ./dsl-parity.nix testContext;
  dsl-validation = import ./dsl-validation.nix testContext;
  emitted-value-safety = import ./emitted-value-safety.nix testContext;
  expr-scalar-safety = import ./expr-scalar-safety.nix testContext;
  expr-token-safety = import ./expr-token-safety.nix testContext;
  ifname-safety = import ./ifname-safety.nix testContext;
  log-prefix-safety = import ./log-prefix-safety.nix testContext;
  module-properties = import ./module-properties.nix testContext;
  named-ref-safety = import ./named-ref-safety.nix testContext;
  parse-check-inputs = import ./parse-check-inputs.nix testContext;
  priority-safety = import ./priority-safety.nix testContext;
  public-surface = import ./public-surface.nix testContext;
  reach = import ./reach.nix testContext;
  ruleset-entries = import ./ruleset-entries.nix testContext;
  restricted-types = import ./restricted-types.nix testContext;
  schema = import ./schema.nix testContext;
  schema-option-tree = import ./schema-option-tree.nix testContext;
  set-datatype-safety = import ./set-datatype-safety.nix testContext;
  statement-bodies = import ./statement-bodies.nix testContext;
  text-block-parity = import ./text-block-parity.nix testContext;
  text-parity = import ./text-parity.nix testContext;
  unit-name-safety = import ./unit-name-safety.nix testContext;
  validate = import ./validate.nix testContext;
  verdict-target-safety = import ./verdict-target-safety.nix testContext;
}
