/*
  Imperative nftables-text rendering and internal object spelling.

  Imperative entries take only a ruleset
  (`{ nftables = [ <command>, ... ]; }`). The table module (../table.nix)
  owns toTextBlock* and table-tree validation, and renders its prepared
  table through `renderTableBlock`, which raises every block-form Refusal.

  Each entry prepares its input once: the imperative entries through
  `prepareRuleset` (lib/prepare-ruleset.nix), as `toJson` does, and
  `renderTableBlock` through `clean` (lib/clean.nix). Nested renderers
  trust their input is already cleaned.
*/
{
  lib,
  clean,
  nftSafeIfname,
  nftSafeLogPrefix,
  nftSafeScalar,
  nftSafeString,
  prepareRuleset,
}:

let
  context = import ./context.nix { inherit lib; };

  # The rendering modules of the renderer `api`, which each of their errors
  # names (ADR 0009) through `fail`.
  modulesFor =
    api:
    let
      fail = import ../fail.nix { } api;
      primitives = import ./primitives.nix {
        inherit
          fail
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
          context
          fail
          lib
          nftSafeScalar
          primitives
          ;
      };
      statements = import ./statements.nix {
        inherit
          context
          expressions
          fail
          lib
          limit
          primitives
          ;
      };
      objects = import ./objects.nix {
        inherit
          context
          expressions
          fail
          lib
          limit
          nftSafeScalar
          primitives
          statements
          ;
      };
      commands = import ./commands.nix {
        inherit
          fail
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

  # Bound before `ruleset`, so each renderer builds its modules once.
  renderRuleset =
    api: pretty:
    let
      inherit (modulesFor api) commands;
      ctx = context.mkCtx { inherit pretty; };
    in
    ruleset:
    let
      # A dropped command, such as a listing's metainfo, renders as null.
      rendered = builtins.filter (entry: entry.text != null) (
        map (cmd: {
          text = commands.renderCommand ctx cmd;
          table = commands.tableOf cmd;
        }) (prepareRuleset api ruleset).nftables
      );
      # Pretty form puts a blank line where the commands move to another
      # table.
      startsTable =
        index: entry: pretty && index > 0 && (builtins.elemAt rendered (index - 1)).table != entry.table;
    in
    # Every line ends with a newline, so renders concatenate.
    lib.concatStrings (
      lib.imap0 (
        index: entry: lib.optionalString (startsTable index entry) "\n" + "${entry.text}\n"
      ) rendered
    );

  # The modules the test-suite internals below read. Every renderer's
  # modules differ only in the name their errors give, so `toText`'s serve.
  testedModules = modulesFor "toText";
in
{
  /*
    Render a ruleset to compact imperative nftables text: one command per
    line, with statements separated by `; ` inside braces.

    The argument is a ruleset (`{ nftables = [ … ]; }`), as `dsl.ruleset`
    builds it. It is cleaned first but not validated as a whole; anything
    else throws, a lone command or a table tree included.

    Returns the `.nft` text as a string, every line ending with a newline,
    so renders concatenate; an empty ruleset renders as "".
  */
  toText = renderRuleset "toText" false;

  /*
    Render a ruleset to multi-line imperative nftables text with indented
    brace blocks, and a blank line where the commands move to another
    table.

    The argument is a ruleset, handled as in `toText`.

    Returns the `.nft` text as a string, every line ending with a newline;
    an empty ruleset renders as "".
  */
  toTextPretty = renderRuleset "toTextPretty" true;

  /*
    Render a table tree's contents in block form, for lib/table.nix; not
    exposed by nftlib. `api` names the block renderer in errors, `pretty`
    selects multi-line output, and `table` is the table module's prepared
    `{ body, chains, objects }`. Returns the block-form text, without the
    `table <family> <name> { … }` wrapper, every line ending with a
    newline.
  */
  renderTableBlock =
    api: pretty:
    let
      inherit (modulesFor api) objects;
      ctx = context.mkCtx {
        inherit pretty;
        block = true;
      };
    in
    table: objects.renderTableBlock ctx (clean table);

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
