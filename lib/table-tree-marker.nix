/*
  The marker that tags a `dsl.table` value as a table tree, shared by the
  DSL that sets it and the modules that read it. The `__` prefix keeps it
  clear of every JSON field name; table preparation strips it before
  emitting commands.
*/
{ }:

let
  marker = "__nftTable";

  # Whether `value` is a table tree.
  isTableTree = value: builtins.isAttrs value && (value.${marker} or false);
in
{
  inherit isTableTree marker;

  /*
    Guard an imperative renderer's argument. `api` names the renderer in
    the error and `value` is its argument. Returns `value` unchanged, and
    throws if it, or an entry of its `nftables` list, is a table tree,
    which only `dsl.ruleset` turns into commands.
  */
  requireNoTableTree =
    api: value:
    let
      entries =
        if builtins.isAttrs value && builtins.isList (value.nftables or null) then value.nftables else [ ];
    in
    if isTableTree value || builtins.any isTableTree entries then
      throw "nix-nftypes: ${api}: got a dsl.table node; wrap it in dsl.ruleset [ … ]"
    else
      value;
}
