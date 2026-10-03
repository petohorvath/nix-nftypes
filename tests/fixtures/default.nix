# Fixtures shared by the unit suites and the live probes.
{ dsl, examples }:
{
  blockTables = import ./block-tables.nix { inherit dsl; };
  commentRulesets = import ./comment-rulesets.nix { inherit dsl; };
  ifnameRulesets = import ./ifname-rulesets.nix { inherit dsl; };
  integrationCases = import ./integration-cases.nix { inherit dsl examples; };

  # A comment the live round trip must preserve byte-for-byte.
  roundTripComment = "round-trip me (with spaces & punct!)";
}
