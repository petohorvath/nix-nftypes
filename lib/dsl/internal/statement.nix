/*
  Statement builders that validate their statement when called, as command
  builders do (../structure/commands.nix): each body is checked against the
  body `types.statement` takes for its tag, so a statement is checked
  wherever it goes, a raw command passed through `dsl.ruleset` included.
  Errors name the builder, `dsl.<name>`: the module system's option paths
  start with it, as in `dsl.log.level`.

  `bodiesByTag` maps each statement tag to its body type
  (lib/schema/statements.nix). Each function takes the builder's `name`,
  as in `dsl.<name>`, and the statement `tag` it builds, which defaults to
  the name: `ctCount` builds a `ct count` statement.

  - `tagged { name; tag ? name; } body`: the statement `{ <tag> = body; }`
    of the builder `dsl.<name>`, such as `jump` or `eq`, once `body`
    validates. Returns the statement.
  - `fromFields { name; tag ? name; prepare ? (location: body: body); }`:
    the builder `dsl.<name>`, which takes one attrset of fields with DSL
    spellings. It checks the attrset is a body, throws for a JSON
    spelling, renames the fields to their JSON keys (./rename.nix), and
    drops the null ones; `prepare` then gets the builder's location
    (./location.nix) and the JSON body, to check it further or to
    normalise a field, such as a set reference. Returns the builder, whose
    result is the statement `tagged` returns.
  - `ref { name; tag ? name; }`: the builder `dsl.<name>.ref`, which takes
    a named object's name, with or without its `@`, or a map expression
    that selects one by key (./reference.nix). Returns the builder, whose
    result is the statement `tagged` returns.
  - `referenceOnly { name; tag ? name; }`: a statement whose only form
    names an object, such as `ct helper`. Returns a variant namespace
    whose `.ref` is `ref { name; tag; }`, and which throws when called,
    pointing to `.ref`.
*/
{ bodiesByTag, lib }:

let
  inherit (import ./location.nix { inherit lib; }) builder fail;
  compact = import ./compact.nix { inherit lib; };
  reference = import ./reference.nix { inherit lib; };
  rename = import ./rename.nix { inherit lib; };
  requireBody = import ./require-body.nix { inherit lib; };
  validate = import ./validate.nix { inherit lib; };

  # The statement `{ <tag> = body; }`, once `body` validates at `location`.
  validated = location: tag: body: {
    ${tag} = validate {
      type = bodiesByTag.${tag};
      value = body;
      inherit location;
    };
  };

  ref =
    {
      name,
      tag ? name,
    }:
    let
      location = builder [
        name
        "ref"
      ];
    in
    object: validated location tag (reference.objectReference location object);
in
{
  inherit ref;

  tagged =
    {
      name,
      tag ? name,
    }:
    validated (builder [ name ]) tag;

  referenceOnly =
    {
      name,
      tag ? name,
    }:
    let
      location = builder [ name ];
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
      prepare ? _location: lib.id,
    }:
    let
      location = builder [ name ];
    in
    fields:
    lib.pipe fields [
      (requireBody location)
      (rename.statement name location)
      compact
      (prepare location)
      (validated location tag)
    ];
}
