# JSON renderer: produces the libnftables-json form consumed by `nft -j -f`.
# `prepareRuleset` is injected from lib/prepare-ruleset.nix, the input step
# the text renderer shares, so neither depends on the other.
{ prepareRuleset }:

{
  /*
    Serialize a ruleset to compact libnftables JSON.

    `ruleset` is `{ nftables = [ … ]; }`, as `dsl.ruleset` builds it. It is
    cleaned first, which drops unset nullable fields and module markers,
    and a rule without `expr` gets the empty list; it is not type-checked.
    Anything else throws, a lone command or a table tree included: wrap it
    in `dsl.ruleset [ … ]`.

    Returns the JSON string.
  */
  toJson = ruleset: builtins.toJSON (prepareRuleset "toJson" ruleset);
}
