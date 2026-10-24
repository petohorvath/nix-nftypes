/*
  Imperative nftables-text rendering and internal object spelling.

  Imperative entries take only a ruleset
  (`{ nftables = [ <command>, ... ]; }`). The table module (../table.nix)
  owns toTextBlock* and table-tree validation, and renders its prepared
  table through `renderTableBlock`, which raises every block-form Refusal.

  Internally we run `clean` (from lib/clean.nix) once at the entry,
  mirroring `toJson`'s contract: nested renderers trust their input is
  already cleaned.
*/
{
  lib,
  clean,
  nftSafeIfname,
  nftSafeLogPrefix,
  nftSafeScalar,
  nftSafeString,
}:

let
  context = import ./context.nix { inherit lib; };
  requireRuleset = import ../require-ruleset.nix { inherit lib; };

  # The rendering modules of the renderer `api`, which each of their errors
  # names (ADR 0009).
  modulesFor =
    api:
    let
      primitives = import ./primitives.nix {
        inherit
          api
          lib
          nftSafeIfname
          nftSafeLogPrefix
          nftSafeScalar
          nftSafeString
          ;
      };
      limit = import ./limit.nix { inherit lib primitives; };
      expressions = import ./expressions.nix {
        inherit
          api
          context
          lib
          nftSafeScalar
          primitives
          ;
      };
      statements = import ./statements.nix {
        inherit
          api
          context
          expressions
          lib
          limit
          primitives
          ;
      };
      objects = import ./objects.nix {
        inherit
          api
          context
          expressions
          lib
          limit
          nftSafeScalar
          primitives
          statements
          ;
      };
      commands = import ./commands.nix {
        inherit
          api
          lib
          limit
          objects
          primitives
          ;
      };
    in
    {
      inherit
        commands
        expressions
        objects
        primitives
        statements
        ;
    };

  renderRuleset =
    api: pretty: ruleset:
    let
      inherit (modulesFor api) commands;
      ctx = context.mkCtx { inherit pretty; };
      cleaned = clean (requireRuleset api ruleset);
    in
    lib.concatStringsSep "\n" (
      # A dropped command, such as a listing's metainfo, renders as null.
      builtins.filter (line: line != null) (map (commands.renderCommand ctx) cleaned.nftables)
    );

  # The modules the test-suite internals below read; any renderer's serve.
  testedModules = modulesFor "toText";
in
{
  /*
    Render a ruleset to compact imperative nftables text: one command per
    line, with statements separated by `; ` inside braces.

    The argument is a ruleset (`{ nftables = [ … ]; }`), as `dsl.ruleset`
    builds it. It is cleaned first but not fully type-checked; anything
    else throws, a lone command or a table tree included.

    Returns the `.nft` text as a string.
  */
  toText = renderRuleset "toText" false;

  /*
    Render a ruleset to multi-line imperative nftables text with indented
    brace blocks.

    The argument is a ruleset, handled as in `toText`.

    Returns the `.nft` text as a string.
  */
  toTextPretty = renderRuleset "toTextPretty" true;

  /*
    Render a table tree's contents in block form, for lib/table.nix; not
    exposed by nftlib. `api` names the block renderer in errors, `pretty`
    selects multi-line output, and `table` is the table module's prepared
    `{ body, chains, objects }`. Returns the block-form text, without the
    `table <family> <name> { … }` wrapper.
  */
  renderTableBlock =
    api: pretty: table:
    (modulesFor api).objects.renderTableBlock (context.mkCtx {
      inherit pretty;
      block = true;
    }) (clean table);

  # Internals for the test suites, not exposed by nftlib: the dispatch
  # tables and block-form field classification read by the schema↔text
  # drift tests, and the primitives the renderer-level safety tests call
  # directly.
  inherit (testedModules.objects) blockFields;
  dispatch = {
    expressionTags = testedModules.expressions.tags;
    objectKinds = testedModules.objects.renderableKinds;
    statementTags = testedModules.statements.tags;
  };
  inherit (testedModules) primitives;
}
