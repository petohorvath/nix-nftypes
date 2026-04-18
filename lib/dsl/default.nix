{ lib }:

# Entry point for the DSL layer. Exposes:
#   expr        — expression combinators (payload, meta, ct, prefix, ...)
#   stmt        — statement combinators (match, verdicts, counter, log, ...)
#   builders    — context-threading tree builders (mkTable, mkChain, mkRule, ...)
# plus a flat re-export of every builder at the top level for convenience.

let
  expr = import ./expressions.nix { inherit lib; };
  stmt = import ./statements.nix { inherit lib; };
  builders = import ./builders.nix { inherit lib; };
in
{
  inherit expr stmt builders;
}
// builders
