/*
  References to named objects, one rule for every builder (ADR 0009): a
  builder takes the name with or without its `@` and emits the spelling
  that nft's JSON parser looks up in that position. `caller` is the
  builder's path under `dsl` (`expr.setRef`), named in errors.

  - `atReference caller name`: a set, map, or flowtable reference. Returns
    `"@<name>"`; nft reads a bare name there as a hostname or a symbol.
  - `objectReference caller ref`: a stateful object reference, such as a
    counter's. Returns the bare name, which nft looks up as written, so
    `"@c"` names no object; a map expression, which selects the object by
    key, passes through.

  Each throws on an empty name and on a value that is neither a name nor,
  for `objectReference`, a map expression, `{ map = …; }`.
*/
{ lib }:

let
  fail = caller: message: throw "nix-nftypes: dsl.${caller}: ${message}";

  nameOf =
    caller: expected: name:
    let
      bare = lib.removePrefix "@" name;
    in
    if bare == "" then fail caller "expected ${expected}, got ${builtins.toJSON name}" else bare;

  atReference =
    caller: name:
    if builtins.isString name then
      "@${nameOf caller "a name" name}"
    else
      fail caller "expected a name string, got ${builtins.typeOf name}";

  objectReference =
    caller: ref:
    if builtins.isString ref then
      nameOf caller "an object name" ref
    else if builtins.isAttrs ref && builtins.attrNames ref == [ "map" ] then
      ref
    else
      fail caller "expected an object name or a map expression, got ${
        if builtins.isAttrs ref then "an attribute set without the one key `map`" else builtins.typeOf ref
      }";
in
{
  inherit atReference objectReference;
}
