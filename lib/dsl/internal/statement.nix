/*
  Statement builders that validate their statement when called, as command
  builders do (../structure/commands.nix): each body is checked against the
  body `types.statement` takes for its tag, so a statement is checked
  wherever it goes, a raw command passed through `dsl.ruleset` included.
  Errors name the builder, `dsl.<name>`: the module system's option paths
  start with it, as in `dsl.log.level`.

  `bodiesByTag` maps each statement tag to its body type
  (lib/schema/statements.nix).

  - `tagged name tag body`: the statement `{ <tag> = body; }` of the
    builder `dsl.<name>`, such as `jump` or `counter.ref`, once `body`
    validates. Returns the statement.
  - `fromFields { name; tag ? name; prepare ? id; }`: the builder
    `dsl.<name>`, which takes one attrset of fields with DSL spellings. It
    checks the attrset is a body, throws for a JSON spelling, renames the
    fields to their JSON keys (./rename.nix), and drops the null ones;
    `prepare` then gets the JSON body, to check it further or to normalise
    a field, such as a set reference. Returns the builder, whose result is
    the statement `tagged` returns.
  - `ref name tag`: the builder `dsl.<name>.ref`, which takes a named
    object's name, with or without its `@`, or a map expression that
    selects one by key (./reference.nix). Returns the builder, whose result
    is the statement `tagged` returns.
  - `referenceOnly name tag`: a statement whose only form names an object,
    such as `ct helper`. Returns a variant namespace whose `.ref` is
    `ref name tag`, and which throws when called, pointing to `.ref`.
*/
{ bodiesByTag, lib }:

let
  inherit (import ./location.nix { inherit lib; }) builder fail;
  compact = import ./compact.nix { inherit lib; };
  reference = import ./reference.nix { inherit lib; };
  rename = import ./rename.nix { inherit lib; };
  requireBody = import ./require-body.nix { inherit lib; };
  validate = import ./validate.nix { inherit lib; };

  /*
    The submodule branch of the union `type` that the module system merges
    `value` with, or `type` itself when that branch is no submodule: an
    `either` takes its left type when `value` passes that type's check, and
    its right one otherwise. A body such as `logBody`, `null` or a
    submodule, is then checked against its submodule, whose errors name the
    field, as in `dsl.log.level`.
  */
  branchFor =
    type: value:
    let
      inherit (type.nestedTypes) left right;
      branch = branchFor (if left.check value then left else right) value;
    in
    if type.name == "either" && branch.name == "submodule" then branch else type;

  tagged = name: tag: body: {
    ${tag} = validate {
      type = branchFor bodiesByTag.${tag} body;
      value = body;
      location = builder (lib.splitString "." name);
    };
  };

  ref =
    name: tag: object:
    tagged "${name}.ref" tag (reference.objectReference "${name}.ref" object);
in
{
  inherit ref tagged;

  referenceOnly =
    name: tag:
    let
      location = builder [ name ];
    in
    {
      ref = ref name tag;
      __functor =
        _self: _:
        fail location "a ${tag} statement names a ${tag} object and has no inline form; write `${name}.ref name`";
    };

  fromFields =
    {
      name,
      tag ? name,
      prepare ? lib.id,
    }:
    fields:
    let
      location = builder [ name ];
    in
    tagged name tag (prepare (compact (rename.statement name location (requireBody location fields))));
}
