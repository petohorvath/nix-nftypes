/*
  References to named objects, one rule for every builder (ADR 0009): a
  builder takes the name with or without its `@` and emits the spelling
  that nft's JSON parser looks up in that position. `location` is the
  builder's location (./location.nix), such as `expr.setRef`'s, named in
  errors.

  - `atReference location name`: a set, map, or flowtable reference.
    Returns `"@<name>"`; nft reads a bare name there as a hostname or a
    symbol.
  - `normaliseAtReference field location body`: `body` with its `field`,
    if given, normalised by `atReference`, for a statement body that names
    a set or map, such as `setStmt`'s `set`. Returns the body.
  - `objectReference location ref`: a stateful object reference, such as
    a counter's. Returns the bare name, which nft looks up as written, so
    `"@c"` names no object; a map expression, which selects the object by
    key, passes through.

  Each throws on an empty name and on a value that is neither a name nor,
  for `objectReference`, a map expression, `{ map = …; }`.
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail;

  nameOf =
    location: expected: name:
    let
      bare = lib.removePrefix "@" name;
    in
    if bare == "" then fail location "expected ${expected}, got ${builtins.toJSON name}" else bare;

  atReference =
    location: name:
    if builtins.isString name then
      "@${nameOf location "a name" name}"
    else
      fail location "expected a name string, got ${builtins.typeOf name}";

  objectReference =
    location: ref:
    if builtins.isString ref then
      nameOf location "an object name" ref
    else if builtins.isAttrs ref && builtins.attrNames ref == [ "map" ] then
      ref
    else
      fail location "expected an object name or a map expression, got ${
        if builtins.isAttrs ref then "an attribute set without the one key `map`" else builtins.typeOf ref
      }";
in
{
  inherit atReference objectReference;

  normaliseAtReference =
    field: location: body:
    body // lib.optionalAttrs (body ? ${field}) { ${field} = atReference location body.${field}; };
}
