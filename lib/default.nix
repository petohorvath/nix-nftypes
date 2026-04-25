{ lib }:

let
  internal = import ./schema/internal.nix { inherit lib; };
  primitives = import ./schema/primitives.nix { inherit lib; };
  expressions = import ./schema/expressions.nix { inherit lib internal primitives; };
  statements = import ./schema/statements.nix {
    inherit lib primitives expressions;
  };
  objects = import ./schema/objects.nix {
    inherit
      lib
      internal
      primitives
      expressions
      statements
      ;
  };
  commands = import ./schema/commands.nix { inherit lib internal objects; };
  clean = import ./clean.nix { inherit lib; };
  json = import ./json { inherit lib clean; };
  text = import ./text { inherit lib clean; };
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
  toJSON = json.toJSON;
  toPretty = json.toPretty;
  cleanValue = clean;

  # Render a value to nftables text syntax (the `.nft` form `nft -f`
  # consumes). Both renderers consume the same validated attrset.
  toText = text.toText;
  toTextPretty = text.toTextPretty;

  # DSL — path-based field access, top-level operators, variant namespaces,
  # declarative table structure. Produces the same attrsets accepted by
  # the types above.
  inherit dsl;
}
