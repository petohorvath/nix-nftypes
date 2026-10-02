/*
  nix-unit entry point. Builds the shared test context once and groups
  each suite's tests under the suite's name.

  Run locally with `nix-unit --flake .#tests`.
*/
{ lib }:
let
  helpers = import ./helpers { inherit lib; };
  testContext = {
    inherit helpers lib;
    inherit (helpers) nftlib;
    fixtures = import ./fixtures { inherit (helpers.nftlib) dsl; };
  };
in
{
  commentSafety = import ./suites/comment-safety.nix testContext;
  ctTimeoutPolicySafety = import ./suites/ct-timeout-policy-safety.nix testContext;
  dslParity = import ./suites/dsl-parity.nix testContext;
  dslValidation = import ./suites/dsl-validation.nix testContext;
  exprScalarSafety = import ./suites/expr-scalar-safety.nix testContext;
  exprTokenSafety = import ./suites/expr-token-safety.nix testContext;
  ifnameSafety = import ./suites/ifname-safety.nix testContext;
  namedRefSafety = import ./suites/named-ref-safety.nix testContext;
  nixpkgsSourcePolicy = import ./suites/nixpkgs-source-policy.nix testContext;
  prioritySafety = import ./suites/priority-safety.nix testContext;
  restrictedTypes = import ./suites/restricted-types.nix testContext;
  schema = import ./suites/schema.nix testContext;
  setDatatypeSafety = import ./suites/set-datatype-safety.nix testContext;
  textBlockParity = import ./suites/text-block-parity.nix testContext;
  textParity = import ./suites/text-parity.nix testContext;
  unitNameSafety = import ./suites/unit-name-safety.nix testContext;
  verdictTargetSafety = import ./suites/verdict-target-safety.nix testContext;
}
