# The shape of a ruleset, shared by `dsl.ruleset`, which splices a ruleset
# passed as a child, and the renderers' input step, which takes only a
# ruleset. Neither validates the commands inside.
_:

let
  # The keys a ruleset may have; cleaning strips a library's `_type` tag.
  rulesetKeys = [
    "_type"
    "nftables"
  ];

  # Whether `value` is a ruleset: an attrset whose `nftables` list holds
  # commands, with no other key but `_type`.
  isRuleset =
    value:
    builtins.isAttrs value
    && builtins.isList (value.nftables or null)
    && builtins.all (name: builtins.elem name rulesetKeys) (builtins.attrNames value);
in
{
  inherit isRuleset;
}
