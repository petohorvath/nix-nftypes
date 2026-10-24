/*
  The marker that tags a `dsl.table` value as a table tree, shared by the
  DSL that sets it and the modules that read it. The `__` prefix keeps it
  clear of every JSON field name; table preparation strips it before
  emitting commands.
*/
_:

let
  marker = "__nftTable";

  # Whether `value` is a table tree.
  isTableTree = value: builtins.isAttrs value && (value.${marker} or false);
in
{
  inherit isTableTree marker;
}
