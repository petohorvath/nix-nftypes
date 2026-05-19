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
                              chain-type×family, chain-type×hook,
                              symbolic priorities, hooks-with-oifname,
                              plus a `priorityIntsByFamily` accessor
                              for the family-appropriate priority
                              table.
    resolvePriority         — symbolic chain priority → int, with
                              family-aware lookup (bridge family
                              overrides default values).
    priorityNameOf          — int → symbolic chain priority (reverse
                              of `resolvePriority`); ints with no
                              canonical symbol pass through unchanged.
    chainTypeFor            — `(family, hook, priority)` → chain type
                              (`"filter"` / `"nat"` / `"route"`); the
                              type the kernel infers from the
                              placement.
    validChainPlacement     — `(family, chainType, hook)` → bool. True
                              iff the kernel will accept a base chain
                              with this triple.
    toJson / toNix          — render a validated value to libnftables-json.
    toText / toTextPretty   — render to nftables `.nft` text syntax in
                              imperative form (`add chain …` / `add rule …`).
    toTextBlock /
      toTextBlockPretty     — render a single `dsl.table` value to block
                              form (the contents of a
                              `table <fam> <name> { … }` wrapper, suitable
                              for embedding in a host module like nixpkgs'
                              `networking.nftables.tables.<n>.content`).
    cleanValue              — strip module-internal markers.
    dsl                     — declarative builder producing values accepted
                              by the types above.
*/
{ lib }:

let
  internal = import ./schema/internal.nix { inherit lib; };
  nftSafeString = import ./nft-safe-string.nix { };
  nftSafeIfname = import ./nft-safe-ifname.nix { };
  primitives = import ./schema/primitives.nix { inherit lib nftSafeString nftSafeIfname; };
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
  text = import ./text {
    inherit
      lib
      clean
      nftSafeString
      nftSafeIfname
      ;
  };
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
    /*
      Recursive expression union plus per-variant body submodules and
      a subset helper. `expressionOf [ kinds... ]` restricts to a
      chosen set of tagged expression kinds — see the helper docstring
      in `lib/schema/expressions.nix` for scope (tagged-only; scalars
      and bare lists are not included).
    */
    inherit (expressions) expression expressionOf;
    # Tagged-only subset of `expression` (no scalar / bare-list branches).
    # Exposed primarily so callers and tests can introspect the full set
    # of tagged expression kinds via `.functor.payload.tags` — used by
    # the schema↔text drift check in tests/default.nix.
    inherit (expressions) taggedExpression;
    expressions = expressions.all;

    /*
      Statement union plus per-variant body submodules and subset
      helpers. `statementOf [ kinds... ]` restricts a `statement`-typed
      field to a subset of statement tags (e.g. match-only or
      verdict-only) with `evalModules`-time validation, replacing
      hand-rolled walker checks downstream. `matchStatement` is the
      pre-applied common case (`statementOf [ "match" ]`).
    */
    inherit (statements) statement statementOf matchStatement;
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
      hooksByChainType
      priorityIntsDefault
      priorityIntsBridge
      priorityIntsByFamily
      hooksWithOifname
      ;
  };

  inherit (compatibility)
    resolvePriority
    validChainPlacement
    priorityNameOf
    chainTypeFor
    ;

  # Render a validated value to libnftables-json.
  toJson = json.toJson;
  toNix = json.toNix;
  cleanValue = clean;

  /*
    Render a validated value to the nftables `.nft` text syntax `nft -f`
    consumes. The imperative entries (`toText` / `toTextPretty`) accept
    the same attrsets the types above produce. The block-form entries
    (`toTextBlock` / `toTextBlockPretty`) accept a single `dsl.table`
    value and emit only the contents of that table — no
    `table <fam> <name> { ... }` wrapper — so a host module like
    nixpkgs' `networking.nftables.tables.<n>.content` can supply the
    wrapper itself. Rules render as inline statements inside their
    parent chain's brace block (vs separate `add rule …` commands).
  */
  toText = text.toText;
  toTextPretty = text.toTextPretty;
  toTextBlock = node: text.toTextBlock (dsl.ruleset [ node ]);
  toTextBlockPretty = node: text.toTextBlockPretty (dsl.ruleset [ node ]);

  /*
    DSL — path-based field access, top-level operators, variant namespaces,
    declarative table structure. Produces attrsets accepted by the types
    above.
  */
  inherit dsl;
}
