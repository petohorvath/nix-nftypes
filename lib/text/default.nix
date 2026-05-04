{ lib, clean }:

# Public entry for the nftables-text renderer.
#
#   toText        — compact form: one command per line, statements
#                   separated by `; ` inside braces.
#   toTextPretty  — multi-line form with indented brace blocks.
#
# Both consume the same validated `ruleset` attrset that toJson consumes
# (`{ nftables = [ <command>, ... ]; }`); the ruleset envelope is unwrapped
# and each command is rendered then joined by newlines.
#
# Internally we run `clean` (from lib/clean.nix) once at the entry, mirroring
# `toJson`'s contract: nested renderers trust their input is already cleaned.

let
  context = import ./context.nix { inherit lib; };
  primitives = import ./primitives.nix { inherit lib; };
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
      ;
  };
  statements = import ./statements.nix {
    inherit
      lib
      context
      primitives
      expressions
      ;
  };
  objects = import ./objects.nix {
    inherit
      lib
      context
      primitives
      expressions
      statements
      ;
  };
  commands = import ./commands.nix {
    inherit
      lib
      primitives
      objects
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
}
