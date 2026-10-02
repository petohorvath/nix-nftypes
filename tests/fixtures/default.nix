# Fixtures shared by the unit suites and the live-parser checks.
{ dsl }:
{
  blockTables = import ./block-tables.nix { inherit dsl; };
  commentRulesets = import ./comment-rulesets.nix { inherit dsl; };
  ifnameRulesets = import ./ifname-rulesets.nix { inherit dsl; };
}
