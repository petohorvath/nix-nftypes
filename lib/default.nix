{ lib }:

let
  primitives = import ./primitives.nix { inherit lib; };
  expressions = import ./expressions.nix { inherit lib primitives; };
  statements = import ./statements.nix {
    inherit lib primitives expressions;
  };
  objects = import ./objects.nix {
    inherit
      lib
      primitives
      expressions
      statements
      ;
  };
  commands = import ./commands.nix { inherit lib objects; };
  render = import ./render.nix { inherit lib; };
  text = import ./text { inherit lib render; };
  dsl = import ./dsl { inherit lib; };
in
{
  # Primitive enum types, portNumber, prefixLength, nullType.
  inherit (primitives) types;

  # Recursive expression type plus individual body types.
  inherit (expressions) expression;
  expressions = expressions.all;

  # Statement type plus individual body types.
  inherit (statements) statement;
  statements = statements.all;

  # Object bodies plus single-tag wrappers and combined unions.
  objects = objects.all;
  inherit (objects)
    addObject
    listObject
    flushObject
    resetObject
    ;

  # Top-level command/ruleset envelopes.
  inherit (commands) command ruleset;

  # Render a value to libnftables-json.
  toJSON = render.toJSON;
  toPretty = render.toPretty;
  cleanValue = render.clean;

  # Render a value to nftables text syntax (the `.nft` form `nft -f`
  # consumes). Both renderers consume the same validated attrset.
  toText = text.toText;
  toTextPretty = text.toTextPretty;

  # DSL — path-based field access, top-level operators, variant namespaces,
  # declarative table structure. Produces the same attrsets accepted by
  # the types above.
  inherit dsl;
}
