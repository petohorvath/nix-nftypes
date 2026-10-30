/*
  Module properties, such as `lib.mkIf` and `lib.mkMerge`, in a value. Only
  an option definition resolves one: a schema type checks the resolved
  value, but the caller keeps the property, which renders as written, as
  `{"condition": …}` or `{"contents": …}`. Every public entry point that
  takes a value throws on one, so a body stays data (ADR 0009).
*/
{ lib }:

let
  # The `_type` of each module property, with the builders that make it.
  builders = {
    "if" = "lib.mkIf";
    merge = "lib.mkMerge";
    override = "lib.mkOverride, as lib.mkDefault and lib.mkForce make";
    order = "lib.mkOrder, as lib.mkBefore and lib.mkAfter make";
    definition = "lib.mkDefinition";
  };

  isProperty = value: builtins.isAttrs value && builders ? ${value._type or ""};

  firstFound = lib.findFirst (found: found != null) null;

  # A value of another kind, such as an option type or a derivation, can
  # refer to itself, so the walk doesn't enter it.
  isOtherKind = value: value ? _type || lib.isDerivation value;

  find =
    path: value:
    if isProperty value then
      { inherit path value; }
    else if builtins.isAttrs value && !(isOtherKind value) then
      firstFound (map (name: find (path ++ [ name ]) value.${name}) (builtins.attrNames value))
    else if builtins.isList value then
      firstFound (lib.imap0 (index: find (path ++ [ (toString index) ])) value)
    else
      null;
in
{
  # The first module property in `value`, depth first, as `{ path; value; }`,
  # where `path` holds the names and list indices that lead to it; or `null`.
  findModuleProperty = find [ ];

  # Whether `value` itself is a module property.
  isModuleProperty = isProperty;

  # The error message for `found`, a result of `findModuleProperty`, without
  # its path, which the caller's location supplies.
  modulePropertyMessage =
    found:
    "got ${builders.${found.value._type}}, which only the module system resolves; build the value with lib.optional, lib.optionalAttrs, or `//`";
}
