/*
  The marker that tags a `dsl.table` value as a Table tree, shared by the
  DSL that sets it and the modules that read it. It follows the nixpkgs
  convention, `_type = "<lib>.<kind>"`, so Cleaning strips it like any
  `_type`, and it never reaches JSON.
*/
_:

let
  type = "nix-nftypes.tableTree";

  # Whether `value` is a Table tree.
  isTableTree = value: builtins.isAttrs value && (value._type or null) == type;
in
{
  inherit isTableTree type;
}
