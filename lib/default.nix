/**
  nix-nftypes: strict Nix types, an ergonomic DSL, and pure renderers for
  nftables rulesets. `docs/api.md` documents every export, and
  `tests/unit/public-surface.nix` pins the list.
*/
{ lib }:

let
  internal = import ./schema/internal.nix { inherit lib; };
  nftSafeString = import ./nft-safe-string.nix { };
  nftSafeIfname = import ./nft-safe-ifname.nix { };
  nftSafeScalar = import ./nft-safe-scalar.nix { };
  nftSafeLogPrefix = import ./nft-safe-log-prefix.nix { inherit nftSafeString; };
  primitives = import ./schema/primitives.nix {
    inherit
      lib
      nftSafeIfname
      nftSafeLogPrefix
      nftSafeString
      ;
  };
  # Mutual reference between `expressions` and `statements`: statements
  # consume `expr`, and elements (defined in expressions) accept the
  # statement keys nft lists for them. Nix's recursive `let` resolves this
  # lazily — both modules are constructed without forcing the
  # cross-reference, which is only forced during value validation (by
  # which point both attrsets exist).
  expressions = import ./schema/expressions.nix {
    inherit
      internal
      lib
      primitives
      statements
      ;
  };
  statements = import ./schema/statements.nix {
    inherit
      expressions
      internal
      lib
      primitives
      ;
  };
  objects = import ./schema/objects.nix {
    inherit
      expressions
      internal
      lib
      primitives
      statements
      ;
  };
  commands = import ./schema/commands.nix { inherit internal lib objects; };
  clean = import ./clean.nix { inherit lib; };
  json = import ./json { inherit clean lib; };
  text = import ./text {
    inherit
      clean
      lib
      nftSafeIfname
      nftSafeLogPrefix
      nftSafeScalar
      nftSafeString
      ;
  };
  tables = import ./table.nix {
    inherit lib text;
    objects = objects.all;
  };
  dsl = import ./dsl {
    inherit lib;
    objects = objects.all;
    inherit (commands) resetOrder;
    inherit (tables) expandTable;
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
    # The tagged forms of `expression`, without its scalar and bare-list
    # branches: the type `expressionOf` restricts, and whose
    # `.functor.payload.tags` lists every expression tag.
    inherit (expressions) taggedExpression;
    expressions = expressions.all;

    /*
      Statement union plus per-variant body submodules and a subset
      helper. `statementOf [ kinds... ]` restricts a `statement`-typed
      field to a subset of statement tags (e.g. match-only or
      verdict-only) with `evalModules`-time validation, replacing
      hand-rolled walker checks downstream.
    */
    inherit (statements) statement statementOf;
    statements = statements.all;

    # Object bodies, single-tag wrappers, combined unions.
    objects = objects.all;
    inherit (objects)
      addObject
      createObject
      deleteObject
      flushObject
      insertObject
      listObject
      readBackObject
      renameObject
      replaceObject
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
    families, symbolic chain priorities, oifname-bearing hooks — and the
    helpers that look placements and priorities up in it. See
    `lib/compatibility.nix` for source-of-truth comments tying each
    table back to `man nft` Tables 6/7 and the relevant kernel headers.
  */
  compatibility = {
    inherit (compatibility)
      chainTypeFor
      familiesByChainType
      hooksByChainType
      hooksByFamily
      hooksWithOifname
      priorityIntsByFamily
      priorityNameOf
      resolvePriority
      validChainPlacement
      ;
  };

  # Serialize after cleaning. These functions do not run arbitrary raw input
  # through `types.ruleset`; callers that need schema validation must do that
  # explicitly.
  inherit (json) toJson toNix;
  cleanValue = clean;

  # The explicit Validation step the renderers leave to the caller.
  validate = import ./validate.nix { inherit lib; };

  /*
    Render schema-shaped values to the nftables `.nft` text syntax `nft -f`
    consumes. The imperative entries (`toText` / `toTextPretty`) accept
    the same attrset shapes the schema and DSL produce, but do not perform a
    complete type-validation pass for raw attrsets. The block-form entries
    (`toTextBlock` / `toTextBlockPretty`) accept a single `dsl.table`
    value and emit only the contents of that table — no
    `table <fam> <name> { ... }` wrapper — so a host module like
    nixpkgs' `networking.nftables.tables.<n>.content` can supply the
    wrapper itself. Rules render as inline statements inside their
    parent chain's brace block (vs separate `add rule …` commands).
  */
  inherit (text) toText toTextPretty;
  inherit (tables) toTextBlock toTextBlockPretty;

  /*
    DSL — path-based field access, top-level operators, variant namespaces,
    and declarative table structure. Structured builders validate assembled
    bodies; `dsl.ruleset` also preserves raw command attrsets as an escape
    hatch.
  */
  inherit dsl;
}
