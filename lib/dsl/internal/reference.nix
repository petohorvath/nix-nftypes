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
  - `referenceOnly caller tag`: a statement whose only form names an
    object, such as `ct helper`. Returns a variant namespace whose `.ref`
    takes what `objectReference` takes and returns `{ <tag> = <ref>; }`,
    and which throws when called, pointing to `.ref`.

  Each throws on an empty name and on a value that is neither a name nor,
  for `objectReference`, an attribute set.
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
    else if builtins.isAttrs ref then
      ref
    else
      fail caller "expected an object name or a map expression, got ${builtins.typeOf ref}";
in
{
  inherit atReference objectReference;

  referenceOnly = caller: tag: {
    ref = ref: { ${tag} = objectReference "${caller}.ref" ref; };
    __functor =
      _self: _:
      fail caller "a ${tag} statement names a ${tag} object and has no inline form; write `${caller}.ref name`";
  };
}
