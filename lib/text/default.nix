{
  lib,
  clean,
  nftSafeString,
  nftSafeIfname,
  nftSafeScalar,
}:

# Imperative nftables-text rendering and internal object spelling.
#
#   toText             — compact imperative form: one command per line,
#                        statements separated by `; ` inside braces.
#   toTextPretty       — multi-line imperative form with indented brace
#                        blocks.
# Imperative entries consume a schema-shaped ruleset attrset
# (`{ nftables = [ <command>, ... ]; }`). The table module (../table.nix)
# owns toTextBlock* and uses the object renderers directly, preserving the
# tree's chain/rule ownership throughout validation and block emission.
#
# Internally we run `clean` (from lib/clean.nix) once at the entry, mirroring
# `toJson`'s contract: nested renderers trust their input is already cleaned.

let
  context = import ./context.nix { inherit lib; };
  primitives = import ./primitives.nix { inherit lib nftSafeString; };
  limit = import ./limit.nix {
    inherit lib primitives;
    inherit (expressions) safeToken;
  };
  # Mutual reference: `statements` consumes `expressions.renderExpression`,
  # while `renderElem` (in expressions) calls back into
  # `statements.renderStatement` to render element-attached `stmt` lists.
  # Recursive `let` resolves the cycle lazily.
  expressions = import ./expressions.nix {
    inherit
      lib
      context
      primitives
      statements
      nftSafeScalar
      ;
  };
  statements = import ./statements.nix {
    inherit
      lib
      context
      primitives
      expressions
      limit
      nftSafeIfname
      ;
  };
  objects = import ./objects.nix {
    inherit
      lib
      context
      primitives
      expressions
      statements
      limit
      nftSafeIfname
      nftSafeScalar
      ;
  };
  commands = import ./commands.nix {
    inherit
      lib
      primitives
      objects
      limit
      ;
  };

  renderRuleset =
    ctx: ruleset:
    let
      cleaned = clean ruleset;
      cmds =
        if cleaned ? nftables then cleaned.nftables else throw "text: ruleset must have a `nftables` key";
    in
    lib.concatMapStringsSep "\n" (commands.renderCommand ctx) cmds;

  toText = renderRuleset (context.mkCtx { pretty = false; });
  toTextPretty = renderRuleset (context.mkCtx { pretty = true; });

in
{
  inherit toText toTextPretty;
  # Internal spelling helpers for lib/table.nix; not exposed by nftlib.
  inherit (objects) renderObject renderChainBlock;
}
