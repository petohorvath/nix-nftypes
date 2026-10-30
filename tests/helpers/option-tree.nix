/*
  Generates schema tests from the option tree: it walks every body (a
  submodule) and every tagged union (an attrTag) reachable from the given
  root types, and derives for each field a value of the wrong type, the
  body without the field when it is optional, the ends of an integer
  range, and each member of an enum the field holds.

  The values come from each field's declared type name, so a field whose
  type is deleted (the module system's `unspecified`) gets none, and its
  tests fail.
*/
{ lib, validates }:
let
  inherit (lib)
    concatMapStringsSep
    concatStringsSep
    findFirst
    mapAttrs
    mapAttrsToList
    ;

  # Type names that have no fields of their own but contain one type.
  elementWrappers = [
    "attrsOf"
    "listOf"
    "nullOr"
  ];

  # `types.oneOf` is a chain of `either`: its alternatives, in order.
  alternatives =
    type:
    if type.name == "either" then
      alternatives type.nestedTypes.left ++ alternatives type.nestedTypes.right
    else
      [ type ];

  hasFields =
    type:
    builtins.elem type.name [
      "attrTag"
      "submodule"
    ];

  # A body's options (without the module system's `_module`), or a tagged
  # union's tags, each an option with a `type`.
  fieldsOf =
    type:
    if type.name == "submodule" then
      removeAttrs (type.getSubOptions [ ]) [ "_module" ]
    else
      type.getSubOptions [ ];

  /*
    A structural key for the walk's visited set. A body is identified by
    its fields' names, type names and descriptions, so the same body
    reached twice is walked once and the recursive expression and
    statement types end. Other types are keyed by their structure, to
    `depth` levels.
  */
  signature =
    depth: type:
    if type.name == "submodule" then
      "submodule{${
        concatStringsSep ";" (
          mapAttrsToList (name: option: "${name}:${option.type.name}:${option.description or ""}") (
            fieldsOf type
          )
        )
      }}"
    else if depth == 0 then
      type.name
    else if type.name == "attrTag" then
      "attrTag{${
        concatStringsSep ";" (
          mapAttrsToList (name: option: "${name}=${signature (depth - 1) option.type}") (fieldsOf type)
        )
      }}"
    else if type.name == "either" then
      "either[${concatMapStringsSep "," (signature (depth - 1)) (alternatives type)}]"
    else if builtins.elem type.name elementWrappers then
      "${type.name}(${signature (depth - 1) type.nestedTypes.elemType})"
    else
      "${type.name}:${type.description}";

  node = path: type: {
    key = signature 3 type;
    inherit path type;
  };

  children =
    { path, type, ... }:
    if hasFields type then
      mapAttrsToList (name: option: node "${path}.${name}" option.type) (fieldsOf type)
    else if type.name == "either" then
      lib.imap0 (index: node "${path}|${toString index}") (alternatives type)
    else if builtins.elem type.name elementWrappers then
      [ (node "${path}[]" type.nestedTypes.elemType) ]
    else
      [ ];

  # The `[lowest highest]` of a `types.ints.between` type.
  betweenRange =
    type:
    map lib.toInt (
      builtins.match "integer between (-?[0-9]+) and (-?[0-9]+) \\(both inclusive\\)" type.description
    );

  # Values that the custom option types of lib/schema/primitives.nix and
  # a match's left side accept (sample) and refuse (wrong value).
  customSamples = {
    comment = "x";
    ifname = "eth0";
    logPrefix = "x";
    matchLeft.meta.key = "mark";
    namedReference = "@x";
    inherit null;
  };
  customWrongValues = {
    comment = "a\"b";
    ifname = "";
    logPrefix = "";
    matchLeft = 1;
    namedReference = "x";
    null = "null";
  };

  unknownType = what: type: throw "option-tree: no ${what} for a field of type `${type.name}'";

  # A value the type accepts, built from its declared type name.
  sample =
    type:
    let
      inherit (type) name;
    in
    if name == "str" then
      "x"
    else if name == "int" || name == "unsignedInt" then
      0
    else if name == "positiveInt" then
      1
    else if name == "intBetween" then
      builtins.head (betweenRange type)
    else if name == "bool" then
      true
    else if name == "enum" then
      builtins.head type.functor.payload.values
    else if name == "nullOr" then
      null
    else if name == "listOf" then
      # Two elements, for the lists with a minimum length.
      lib.replicate 2 (sample type.nestedTypes.elemType)
    else if name == "attrsOf" then
      { a = sample type.nestedTypes.elemType; }
    else if name == "either" then
      sample (builtins.head (alternatives type))
    else if name == "attrTag" then
      let
        tag = builtins.head (builtins.attrNames (fieldsOf type));
      in
      {
        ${tag} = sample (fieldsOf type).${tag}.type;
      }
    else if name == "submodule" then
      bodyWithout type null
    else
      customSamples.${name} or (unknownType "sample" type);

  isOptional = option: option.type.name == "nullOr" || option ? default;

  # Whether a body passes its type's check and the invariant the type
  # applies to a merged value, such as a NAT body's address or port.
  passes = type: value: type.check value && (type.invariant or (_: true)) value;

  # The smallest body that passes the body's own check: its required
  # fields, plus the first optional field (other than `omitted`) that a
  # body-level check needs, such as a NAT address.
  bodyWithout =
    type: omitted:
    let
      fields = fieldsOf type;
      required = mapAttrs (_: option: sample option.type) (
        lib.filterAttrs (_: option: !isOptional option) fields
      );
      optionalNames = builtins.filter (name: name != omitted && isOptional fields.${name}) (
        builtins.attrNames fields
      );
      withOne = map (name: required // { ${name} = sample fields.${name}.type.nestedTypes.elemType; }) (
        builtins.filter (name: fields.${name}.type.name == "nullOr") optionalNames
      );
    in
    findFirst (passes type) (throw "option-tree: no body of `${type.description}' passes its check") (
      [ required ] ++ withOne
    );

  noSuchTag."nftypes-no-such-tag" = null;

  # A value of the wrong type, built from the declared type name.
  wrongValue =
    type:
    let
      inherit (type) name;
    in
    if name == "str" then
      1
    else if
      builtins.elem name [
        "int"
        "intBetween"
        "positiveInt"
        "unsignedInt"
      ]
    then
      "1"
    else if name == "bool" then
      "true"
    else if name == "enum" then
      "nftypes-not-in-enum"
    else if name == "nullOr" then
      wrongValue type.nestedTypes.elemType
    else if name == "listOf" then
      lib.replicate 2 (wrongValue type.nestedTypes.elemType)
    else if name == "attrsOf" then
      { a = wrongValue type.nestedTypes.elemType; }
    else if name == "either" then
      # The first alternative's wrong value that no alternative accepts.
      let
        choices = alternatives type;
      in
      findFirst (value: !(lib.any (choice: choice.check value) choices)) 1.5 (map wrongValue choices)
    else if name == "attrTag" then
      noSuchTag
    else if name == "submodule" then
      "nftypes-not-a-body"
    else
      customWrongValues.${name} or (unknownType "wrong value" type);

  # The integer type under a field's `nullOr`, or null.
  integerBounds =
    type:
    if type.name == "nullOr" then
      integerBounds type.nestedTypes.elemType
    else if type.name == "unsignedInt" then
      { lowest = 0; }
    else if type.name == "positiveInt" then
      { lowest = 1; }
    else if type.name == "intBetween" then
      { between = true; }
    else
      null;

  # The enum members a field's type accepts, with the field value holding
  # each: [ { value; wrapped; } ]. `depth` bounds the descent, since the
  # recursive expression type holds a list of itself.
  enumMembers =
    depth: type:
    let
      inside = wrap: map (member: member // { wrapped = wrap member.wrapped; });
      nested = enumMembers (depth - 1);
    in
    if type.name == "enum" then
      map (value: {
        inherit value;
        wrapped = value;
      }) type.functor.payload.values
    else if depth == 0 then
      [ ]
    else if type.name == "nullOr" then
      nested type.nestedTypes.elemType
    else if type.name == "listOf" then
      inside (value: [ value ]) (nested type.nestedTypes.elemType)
    else if type.name == "attrsOf" then
      inside (value: { a = value; }) (nested type.nestedTypes.elemType)
    else if type.name == "either" then
      lib.concatMap nested (alternatives type)
    else
      [ ];

  # The bodies and tagged unions reachable from `roots`, each named by the
  # first root path that reaches it.
  nodesFrom =
    roots:
    builtins.filter (node: hasFields node.type) (
      builtins.genericClosure {
        startSet = mapAttrsToList node roots;
        operator = children;
      }
    );
in
{
  /*
    Walks the option tree from `roots` (`{ <path> = type; }`) and returns
    its fields:

      [ { node; field; path; type; option; } ]

    where `node` is the body or tagged union holding the field, `type` is
    that node's type and `path` is `<node path>.<field>`. A node is named
    by the first root path that reaches it.
  */
  fieldsFrom =
    roots:
    lib.concatMap (
      { path, type, ... }:
      mapAttrsToList (field: option: {
        node = path;
        path = "${path}.${field}";
        inherit field option type;
      }) (fieldsOf type)
    ) (nodesFrom roots);

  # The bodies reachable from `roots`: [ { path; type; } ].
  bodiesFrom =
    roots:
    map (node: { inherit (node) path type; }) (
      builtins.filter (node: node.type.name == "submodule") (nodesFrom roots)
    );

  # nix-unit test that a body's smallest valid value, the base of its
  # fields' tests, validates.
  bodyTest =
    { type, ... }:
    {
      expr = validates type (bodyWithout type null);
      expected = true;
    };

  /*
    nix-unit tests for one field. `range` is the expected
    `[ lowest highest ]` of a `types.ints.between` field, from the
    caller's hand-written list, so a changed bound fails a test.
    `requiredByCheck` is whether the body's own check needs the optional
    field, as a FIB lookup needs its flags, also from a hand-written list.

    - wrongType: the body with the field set to a wrong value is
      rejected (for a tag: the tag with a wrong body).
    - omitted: an optional field left out still validates, or fails
      where `requiredByCheck`, and the field declares a null default.
    - lowest/highest/belowLowest/aboveHighest: the integer range.
  */
  fieldTests =
    {
      field,
      option,
      range ? null,
      requiredByCheck ? false,
      type,
      ...
    }:
    let
      isTag = type.name == "attrTag";
      base = if isTag then { } else bodyWithout type null;
      withValue = value: base // { ${field} = value; };
      accepts = value: {
        expr = validates type (withValue value);
        expected = true;
      };
      # Forced outside `validates`, whose `tryEval` would take a missing
      # wrong value (a thrown error) for a rejection.
      rejects = value: {
        expr = builtins.deepSeq (withValue value) (validates type (withValue value));
        expected = false;
      };
      bounds = integerBounds option.type;
      lowest = if bounds ? between then builtins.head range else bounds.lowest;
    in
    {
      wrongType = rejects (wrongValue option.type);
    }
    // lib.optionalAttrs isTag { accepted = accepts (sample option.type); }
    // lib.optionalAttrs (!isTag && isOptional option) {
      # The module system gives an unset `nullOr` option null, so the body
      # validates even without the field's `default`; the declared null
      # default is what the option's documentation shows.
      omitted = {
        expr = {
          validates =
            if requiredByCheck then
              validates type (removeAttrs (bodyWithout type null) [ field ])
            else
              validates type (bodyWithout type field);
          default = option.default or "no default";
        };
        expected = {
          validates = !requiredByCheck;
          default = null;
        };
      };
    }
    // lib.optionalAttrs (!isTag && bounds != null) (
      {
        lowest = accepts lowest;
        belowLowest = rejects (lowest - 1);
      }
      // lib.optionalAttrs (bounds ? between) {
        highest = accepts (lib.last range);
        aboveHighest = rejects (lib.last range + 1);
      }
    );

  /*
    nix-unit tests that a field accepts each member of the enums its type
    holds (under `nullOr`, `listOf`, `attrsOf` and `oneOf`), keyed by the
    member: `{ <member> = test; }`. Deleting a member drops its test, which
    the caller's count pin sees. `memberBody`, from the caller's
    hand-written list, takes a member and returns the body to test it in,
    for a field whose members the body's check accepts only beside another
    value, as a ct direction needs a key that takes one.
  */
  memberTests =
    {
      field,
      option,
      type,
      memberBody ? null,
      ...
    }:
    let
      fields = fieldsOf type;
      # Every optional field set, for the bodies whose fields go together,
      # such as a base chain's type, hook and prio.
      full =
        bodyWithout type null
        // mapAttrs (_: option: sample option.type.nestedTypes.elemType) (
          lib.filterAttrs (_: option: option.type.name == "nullOr") fields
        );
      # The smallest body, else the full one, that passes the body's check
      # with the field set to `value`.
      withValue =
        value:
        let
          bodies = [
            (bodyWithout type null)
            full
          ];
          candidates = map (body: body // { ${field} = value; }) (
            if type.name == "attrTag" then [ { } ] else bodies
          );
        in
        findFirst (passes type) (builtins.head candidates) candidates;
    in
    lib.listToAttrs (
      map (member: {
        name = toString member.value;
        value = {
          expr = validates type (
            if memberBody == null then withValue member.wrapped else memberBody member.value
          );
          expected = true;
        };
      }) (enumMembers 3 option.type)
    );

  # The enum types among `roots` (`{ <path> = type; }`), such as
  # `types.family`: [ { path; type; } ].
  enumsFrom =
    roots:
    mapAttrsToList (path: type: { inherit path type; }) (
      lib.filterAttrs (_: type: type.name == "enum") roots
    );

  # nix-unit tests that an enum type accepts each of its members, keyed
  # by the member.
  enumTests =
    { type, ... }:
    lib.listToAttrs (
      map (value: {
        name = toString value;
        value = {
          expr = validates type value;
          expected = true;
        };
      }) type.functor.payload.values
    );

  # Whether a field's integer type is a `types.ints.between` range.
  isRange = { option, ... }: (integerBounds option.type).between or false;

}
