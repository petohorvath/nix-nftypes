# Fixtures shared by the unit suites and the live probes.
{
  exampleChildren,
  examples,
  lib,
  nftlib,
  paritySuites,
}:
let
  inherit (nftlib) dsl;
in
rec {
  blockTables = import ./block-tables.nix { inherit dsl; };
  chainPlacement = import ./chain-placement.nix { inherit lib nftlib; };
  commentRulesets = import ./comment-rulesets.nix { inherit dsl; };
  ifnameRulesets = import ./ifname-rulesets.nix { inherit dsl; };
  integrationCaseNames = import ./integration-case-names.nix;
  integrationCases = import ./integration-cases.nix {
    inherit
      blockTables
      dsl
      exampleChildren
      examples
      lib
      ;
  };
  # A ruleset whose only interesting field is one log statement's prefix.
  logPrefixRuleset =
    prefix:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ (dsl.log { inherit prefix; }) ] ];
        };
      })
    ];
  nftMisbehaviour = import ./nft-misbehaviour.nix { };
  parseCheck = import ./parse-check.nix {
    inherit
      dsl
      lib
      nftlib
      paritySuites
      ;
  };
  reach = import ./reach.nix { };
  renderEquivalence = import ./render-equivalence.nix { inherit integrationCases lib nftlib; };

  # A comment the live round trip must preserve byte-for-byte.
  roundTripComment = "round-trip me (with spaces & punct!)";

  # A comment with byte 0xA0, in U+00A0 (no-break space) and U+00E0. nft's
  # lexer takes every byte but `"` inside a quoted string, so both forms
  # must load it as written.
  byteA0Comment = builtins.fromJSON ''"no-break\u00a0space, \u00e0 la carte"'';
}
