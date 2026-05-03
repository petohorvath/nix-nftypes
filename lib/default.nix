/*
  nix-nft-types — strict NixOS-style schema for libnftables JSON values,
  plus matching renderers and an ergonomic DSL.

  Outputs:
    types                   — every schema type (primitive enums plus
                              composable submodule types).
    enums                   — flat lists for every primitive enum, e.g.
                              `enums.family = [ "ip" "ip6" … ]`. Same
                              binding as the `types.enum` definitions.
    compatibility           — kernel/man reference data: family×hook,
                              chain-type×family, symbolic priorities,
                              hooks-with-oifname.
    resolvePriority         — symbolic chain priority → int, with
                              family-aware lookup (bridge family
                              overrides default values).
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
  # Mutual reference between `expressions` and `statements`: statements
  # consume `expr`, and elements (defined in expressions) accept a `stmt`
  # list. Nix's recursive `let` resolves this lazily — both modules are
  # constructed without forcing the cross-reference, which is only forced
  # during value validation (by which point both attrsets exist).
  expressions = import ./schema/expressions.nix {
    inherit
      lib
      internal
      primitives
      statements
      ;
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
  compatibility = import ./compatibility.nix;
in
{
  /*
    All schema types in one namespace, mirroring `lib.types`. Primitive
    enums (family, hook, portNumber, …) sit alongside composable
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

  /*
    Flat value lists for every primitive enum, sourced from the same
    binding the `types.enum` definitions read. Useful for downstream
    consumers (zone libraries, validators, doc generators) that want
    the raw list without reaching into `types.<x>.functor.payload.values`.
  */
  enums = primitives.enumValues;

  /*
    Kernel/man reference data — family×hook compatibility, chain-type
    families, symbolic chain priorities, oifname-bearing hooks. See
    `lib/compatibility.nix` for source-of-truth comments tying each
    table back to `man nft` Tables 6/7 and the relevant kernel headers.
  */
  compatibility = {
    inherit (compatibility)
      hooksByFamily
      familiesByChainType
      priorityIntsDefault
      priorityIntsBridge
      hooksWithOifname
      ;
  };

  inherit (compatibility) resolvePriority;

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
