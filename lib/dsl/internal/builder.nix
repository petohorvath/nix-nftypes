/*
  Builders that validate their body when called, as command builders do
  (../structure/commands.nix): each body is checked against the body its
  tag takes in a union, so a statement or expression is checked wherever
  it goes, a raw command passed through `dsl.ruleset` included. Errors
  name the builder: the module system's option paths start with it, as in
  `dsl.log.level` or `dsl.expr.ct.key`.

  Takes `bodiesByTag`, which maps each tag to its body type
  (lib/schema/statements.nix, lib/schema/expressions.nix); `namespace`,
  the builders' path under `dsl`, `[ ]` for statements and `[ "expr" ]`
  for expressions; and `renames`, which takes a builder's name and returns
  the check and rename of its fields: ./rename.nix's `statement` for the
  statement builders, and none for the expression builders, whose fields
  take nft's words. Each builder function below takes the builder's
  `name`, as in `dsl.<namespace>.<name>`, and the `tag` it builds, which
  defaults to the name: `ctCount` builds a `ct count` statement.

  - `tagged { name; tag ? name; type ? bodiesByTag.${tag}; } body`: the
    value `{ <tag> = body; }` of the builder `name`, such as `jump`, `eq`,
    or `expr.concat`, once `body` validates against `type`. A builder that
    builds one form of its tag's body, such as `expr.payloadRaw`, gives
    that form as `type`. Returns the value.
  - `locationOf names`: the location (./location.nix) of the builder at
    `names` under the namespace, as in `locationOf [ "set" ]`.
  - `fromFields { name; tag ? name; type ? bodiesByTag.${tag}; prepare ?
    (location: body: body); }`: the builder `name`, which takes one
    attrset of fields with DSL spellings. It checks the attrset is a
    body, checks and renames its fields with `renames`, and drops the null
    ones; `prepare` then gets the builder's location and the JSON body, to
    check it further or to normalise a field, such as a set reference.
    Returns the builder, whose result is the value `tagged` returns.

  `ref` and `referenceOnly` build statements only:

  - `ref { name; tag ? name; }`: the statement builder `dsl.<name>.ref`,
    which takes a named object's name, with or without its `@`, or a map
    expression that selects one by key (./reference.nix). Returns the
    builder, whose result is the statement `tagged` returns.
  - `referenceOnly { name; tag ? name; }`: a statement whose only form
    names an object, such as `ct helper`. Returns a variant namespace
    whose `.ref` is `ref { name; tag; }`, and which throws when called,
    pointing to `.ref`.
*/
{
  bodiesByTag,
  lib,
  namespace ? [ ],
  renames ? _name: _location: lib.id,
}:

let
  inherit (import ./location.nix { inherit lib; }) builder fail;
  compact = import ./compact.nix { inherit lib; };
  reference = import ./reference.nix { inherit lib; };
  requireBody = import ./require-body.nix { inherit lib; };
  validate = import ./validate.nix { inherit lib; };

  locationOf = names: builder (namespace ++ names);

  # The value `{ <tag> = body; }`, once `body` validates against `type` at
  # `location`.
  validated = location: tag: type: body: {
    ${tag} = validate {
      inherit type location;
      value = body;
    };
  };

  ref =
    {
      name,
      tag ? name,
    }:
    let
      location = locationOf [
        name
        "ref"
      ];
    in
    object: validated location tag bodiesByTag.${tag} (reference.objectReference location object);
in
{
  inherit locationOf ref;

  tagged =
    {
      name,
      tag ? name,
      type ? bodiesByTag.${tag},
    }:
    validated (locationOf [ name ]) tag type;

  referenceOnly =
    {
      name,
      tag ? name,
    }:
    let
      location = locationOf [ name ];
    in
    {
      ref = ref { inherit name tag; };
      __functor =
        _self: _:
        fail location "a ${tag} statement names a ${tag} object and has no inline form; write `${name}.ref name`";
    };

  fromFields =
    {
      name,
      tag ? name,
      type ? bodiesByTag.${tag},
      prepare ? _location: lib.id,
    }:
    let
      location = locationOf [ name ];
    in
    fields:
    lib.pipe fields [
      (requireBody location)
      (renames name location)
      compact
      (prepare location)
      (validated location tag type)
    ];
}
