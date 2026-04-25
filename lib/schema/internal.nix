{ lib }:

# Helpers shared across schema modules. Kept private to lib/schema/ — none of
# these are part of the public API.

let
  inherit (lib) types mkOption;
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
      sub = types.submodule { inherit options; };
      base =
        v:
        builtins.isAttrs v
        && lib.all (k: v ? ${k}) requireKeys
        && lib.all (k: !(v ? ${k})) forbidKeys;
    in
    types.addCheck sub (
      v: base v && (if extraCheck == null then true else extraCheck v)
    );

  # Like `types.listOf t` but constrained to exactly `n` elements
  # (e.g. range expressions are 2-element lists).
  listOfLen = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs == n);

  # Like `types.listOf t` but constrained to at least `n` elements
  # (e.g. binary-op expressions need ≥ 2 operands).
  listOfMinLen = n: t: types.addCheck (types.listOf t) (xs: builtins.length xs >= n);

  # "Named reference (string) OR inline body" union — the shape used by
  # quota and limit statements where the user either points at a
  # pre-declared object by name (`{quota = "name"}`) or inlines the
  # body (`{quota = {val;val_unit;…}}`). Counter (parser_json.c:1914-1915)
  # also accepts `null` and is built as `oneOf [nullType (refOrInline …)]`
  # at the call site rather than parameterising this helper.
  refOrInline = inlineBody: types.either types.str inlineBody;

  # Trivial mkOption with just a `type` set — used as the leaf option for
  # `types.attrTag` discriminated unions.
  tagOpt = type: mkOption { inherit type; };

  # Single-tag attrTag wrapper:
  #   wrap "table" tableBody == types.attrTag { table = mkOption { type = …; }; }
  wrap = key: body: types.attrTag { ${key} = mkOption { type = body; }; };
}
