/*
  Helpers shared across schema modules. Kept private to lib/schema/; none
  of these are part of the public API.
*/
{ lib }:

let
  inherit (lib) mkOption types;
  inherit (import ../describe.nix { inherit lib; }) describe;

  # Leaf option for one `types.attrTag` choice. Tag values are deliberately
  # required, so the option has no default.
  tagOption =
    tag: type:
    mkOption {
      inherit type;
      description = "`${tag}` body";
    };

  # `types.attrTag` over an attrset of tag → body type.
  taggedUnion = bodies: types.attrTag (lib.mapAttrs tagOption bodies);

  # `type` with `description`. The module system re-creates a type an
  # option declares (`substSubModules`), which drops an overridden
  # description; re-apply it there, so an error names the type as given.
  withDescription =
    description: type:
    type
    // {
      inherit description;
      substSubModules = modules: withDescription description (type.substSubModules modules);
    };

  /*
    The Restricted type that `types.statementOf` and `types.expressionOf`
    build: the tagged union of `bodiesByTag` restricted to `tags`,
    described as `<label> (one of: "<tag>", …)`. `api` names the helper in
    its errors, and `noun` the layer whose tags it takes. Throws when the
    type is built, so a typo surfaces before any value is checked.
  */
  restrictedUnion =
    {
      api,
      noun,
      label,
      bodiesByTag,
    }:
    tags:
    let
      fail = import ../fail.nix { } api;
      expected = "expected a list of ${noun} tags (strings)";
      valid = lib.attrNames bodiesByTag;
      nonStrings = builtins.filter (tag: !builtins.isString tag) tags;
      invalid = lib.subtractLists valid tags;
      renderList = lib.concatMapStringsSep ", " (tag: ''"${tag}"'');
    in
    if !builtins.isList tags then
      fail "${expected}, got ${describe tags}"
    else if tags == [ ] then
      fail "expected a non-empty list of ${noun} tags, got an empty list"
    else if nonStrings != [ ] then
      fail "${expected}, got a list holding ${describe (builtins.head nonStrings)}"
    else if invalid != [ ] then
      fail "unknown ${noun} tag(s): ${renderList invalid}. Valid tags: ${renderList valid}."
    else
      withDescription "${label} (one of: ${renderList tags})" (
        taggedUnion (lib.getAttrs tags bodiesByTag)
      );

  /*
    A body value is data: an attrset of fields. `types.submodule` also takes
    a module function or a path, so a path-like name such as "/sp1" in a
    union with a body was imported as a file, which aborts evaluation.
    `_module` would reconfigure the body's evaluation (`_module.check =
    false` lets unknown fields through).
  */
  isData = v: builtins.isAttrs v && !(v ? _module);

  /*
    Submodule with a key-presence (and optional value) discriminator. Wraps
    the submodule in addCheck so `types.oneOf` can route correctly between
    siblings that share the same nominal shape (e.g. raw / tunnel / named
    payload, ERSPAN v1 / v2, …), and so a body declared directly (an
    attrTag tag) rejects a value that fails the check. `description`
    names the constraint in that error.

      discriminatedSubmodule {
        options = { … };
        requireKeys = [ "base" "offset" "len" ];
        forbidKeys  = [ "tunnel" ];
        extraCheck  = v: (v.version or null) == 2;   # optional value check
      }
  */
  discriminatedSubmodule =
    {
      options,
      requireKeys ? [ ],
      forbidKeys ? [ ],
      extraCheck ? null,
      description ? null,
    }:
    let
      hasExpectedKeys =
        v: isData v && lib.all (k: v ? ${k}) requireKeys && lib.all (k: !(v ? ${k})) forbidKeys;
      check = v: hasExpectedKeys v && (if extraCheck == null then true else extraCheck v);
      # The module system re-creates a submodule declared by an option
      # (`substSubModules`), which drops an `addCheck`; re-apply it there.
      withCheck =
        submodule:
        types.addCheck submodule check
        // {
          substSubModules = modules: withCheck (submodule.substSubModules modules);
        }
        // lib.optionalAttrs (description != null) { inherit description; };
    in
    withCheck (types.submodule { inherit options; });
in
{
  inherit discriminatedSubmodule;

  # `types.submodule` for a schema body: it takes only an attrset of its
  # fields (see `isData`), so a string in a union with a body is always a
  # name and never a module path.
  submodule = { options }: discriminatedSubmodule { inherit options; };

  # Like `types.listOf t` but constrained to exactly `n` elements
  # (e.g. range expressions are 2-element lists).
  listOfLen = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs == n);

  # Like `types.listOf t` but constrained to at least `n` elements
  # (e.g. binary-op expressions need ≥ 2 operands).
  listOfMinLen = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs >= n);

  # "Named-object reference OR inline body" union — the shape used by
  # stateful statements (counter, quota, limit, ct count) where the user
  # either references a pre-declared object or inlines the body. nftables
  # parses a reference as an expression (objref_stmt_alloc): a name
  # (`{quota = "name";}`) or a map selecting one
  # (`{quota = {map = …;};}`). The reference type comes first so its
  # single-key `map` tag routes before the permissive inline submodule.
  # Counter (parser_json.c:1914-1915) also accepts `null` and is built as
  # `oneOf [nullLiteral (refOrInline …)]` at the call site.
  refOrInline = objectRef: inlineBody: types.either objectRef inlineBody;

  inherit restrictedUnion taggedUnion;

  # Single-tag attrTag wrapper:
  #   wrap "table" tableBody
  #   == taggedUnion { table = tableBody; }
  wrap = key: body: taggedUnion { ${key} = body; };
}
