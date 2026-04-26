/*
  nix-nft-types — strict NixOS-style schema for libnftables JSON values,
  plus matching renderers and an ergonomic DSL.

  Outputs:
    types                   — every schema type (primitive enums plus
                              composable submodule types).
    toJSON / toPretty       — render a validated value to libnftables-json.
    toText / toTextPretty   — render to nftables `.nft` text syntax.
    cleanValue              — strip module-internal markers.
    dsl                     — declarative builder producing values accepted
                              by the types above.
*/
{ lib }:

let
  internal = import ./schema/internal.nix { inherit lib; };
  primitives = import ./schema/primitives.nix { inherit lib; };
  expressions = import ./schema/expressions.nix {
    inherit lib internal primitives;
  };
  statements = import ./schema/statements.nix {
    inherit
      lib
      internal
      primitives
      expressions
      ;
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
  dsl = import ./dsl {
    inherit lib;
    objects = objects.all;
  };
in
{
  /*
    All schema types in one namespace, mirroring `lib.types`. Primitive
    enums (familyType, hookType, portNumber, …) sit alongside composable
    submodule types (expression, statement, command, …) and per-variant
    body namespaces (expressions, statements, objects).
  */
  types = primitives.types // {
    # Recursive expression union plus per-variant body submodules.
    inherit (expressions) expression;
    expressions = expressions.all;

    # Statement union plus per-variant body submodules.
    inherit (statements) statement;
    statements = statements.all;

    # Object bodies, single-tag wrappers, combined unions.
    objects = objects.all;
    inherit (objects)
      addObject
      listObject
      flushObject
      resetObject
      ;

    # Top-level command/ruleset envelopes.
    inherit (commands) command ruleset;
  };

  # Render a validated value to libnftables-json.
  toJSON = json.toJSON;
  toPretty = json.toPretty;
  cleanValue = clean;

  /*
    Render a validated value to the nftables `.nft` text syntax `nft -f`
    consumes. Both renderers accept the same attrsets the types above
    produce.
  */
  toText = text.toText;
  toTextPretty = text.toTextPretty;

  /*
    DSL — path-based field access, top-level operators, variant namespaces,
    declarative table structure. Produces attrsets accepted by the types
    above.
  */
  inherit dsl;
}
