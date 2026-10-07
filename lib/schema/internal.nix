/*
  Helpers shared across schema modules. Kept private to lib/schema/; none
  of these are part of the public API.
*/
{ lib }:

let
  inherit (lib) mkOption types;

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
in
{
  # Submodule with a key-presence (and optional value) discriminator. Wraps
  # the submodule in addCheck so `types.oneOf` can route correctly between
  # siblings that share the same nominal shape (e.g. raw / tunnel / named
  # payload, ERSPAN v1 / v2, …).
  #
  #   discriminatedSubmodule {
  #     options = { … };
  #     requireKeys = [ "base" "offset" "len" ];
  #     forbidKeys  = [ "tunnel" ];
  #     extraCheck  = v: (v.version or null) == 2;   # optional value check
  #   }
  discriminatedSubmodule =
    {
      options,
      requireKeys ? [ ],
      forbidKeys ? [ ],
      extraCheck ? null,
    }:
    let
      submodule = types.submodule { inherit options; };
      hasExpectedKeys =
        v: builtins.isAttrs v && lib.all (k: v ? ${k}) requireKeys && lib.all (k: !(v ? ${k})) forbidKeys;
    in
    types.addCheck submodule (
      v: hasExpectedKeys v && (if extraCheck == null then true else extraCheck v)
    );

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

  inherit taggedUnion;

  # Single-tag attrTag wrapper:
  #   wrap "table" tableBody
  #   == taggedUnion { table = tableBody; }
  wrap = key: body: taggedUnion { ${key} = body; };
}
